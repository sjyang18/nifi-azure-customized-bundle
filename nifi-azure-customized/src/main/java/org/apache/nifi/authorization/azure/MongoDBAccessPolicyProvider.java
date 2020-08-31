/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.authorization.azure;


import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.mongodb.MongoClientURI;

import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.AccessPolicyProviderInitializationContext;
import org.apache.nifi.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.authorization.ConfigurableAccessPolicyProvider;
import org.apache.nifi.authorization.FlowInfo;
import org.apache.nifi.authorization.FlowParser;
import org.apache.nifi.authorization.Group;
import org.apache.nifi.authorization.RequestAction;
import org.apache.nifi.authorization.User;
import org.apache.nifi.authorization.UserGroupProvider;
import org.apache.nifi.authorization.UserGroupProviderLookup;
import org.apache.nifi.authorization.annotation.AuthorizerContext;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;
import org.apache.nifi.authorization.exception.UninheritableAuthorizationsException;
import org.apache.nifi.authorization.util.IdentityMapping;
import org.apache.nifi.authorization.util.IdentityMappingUtil;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.web.api.dto.PortDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

public class MongoDBAccessPolicyProvider implements ConfigurableAccessPolicyProvider {

    private static final Logger logger = LoggerFactory.getLogger(MongoDBAccessPolicyProvider.class);

    static final RequestAction READ_CODE = RequestAction.READ;
    static final RequestAction WRITE_CODE = RequestAction.WRITE;

    static final String PROP_NODE_IDENTITY_PREFIX = "Node Identity ";
    static final String PROP_NODE_GROUP_NAME = "Node Group";
    static final String PROP_USER_GROUP_PROVIDER = "User Group Provider";
    static final String PROP_MONGODB_CONNECTION_STR = "MongoDB Connection String for Authorizations";
    static final String PROP_MONGODB_DB_NAME = "MongoDB DB Name for Authorizations";
    static final String PROP_INITIAL_ADMIN_IDENTITY = "Initial Admin Identity";
    static final Pattern NODE_IDENTITY_PATTERN = Pattern.compile(PROP_NODE_IDENTITY_PREFIX + "\\S+");

    private NiFiProperties properties;
    private String rootGroupId;
    private String initialAdminIdentity;
    private Set<String> nodeIdentities;
    private String nodeGroupIdentifier;
    private List<PortDTO> ports = new ArrayList<>();
    private List<IdentityMapping> identityMappings;
    private List<IdentityMapping> groupMappings;

    private UserGroupProvider userGroupProvider;
    private UserGroupProviderLookup userGroupProviderLookup;
    private AccessPolicyDataStore  policyDataStore;

    @Override
    public void initialize(AccessPolicyProviderInitializationContext initializationContext) throws AuthorizerCreationException {
        userGroupProviderLookup = initializationContext.getUserGroupProviderLookup();
    }

    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        try {
            final PropertyValue connectionString = configurationContext.getProperty(PROP_MONGODB_CONNECTION_STR);
            final PropertyValue dbName = configurationContext.getProperty(PROP_MONGODB_DB_NAME);
            if(!connectionString.isSet() && !dbName.isSet()){
                throw new AuthorizerCreationException("MongoDB connection string and dbname for Authorizations must be specified");
            }
            final MongoClientURI mongoClientURI = new MongoClientURI(connectionString.getValue());
            policyDataStore = new AccessPolicyDataStore(mongoClientURI, dbName.getValue());

            final PropertyValue userGroupProviderIdentifier = configurationContext.getProperty(PROP_USER_GROUP_PROVIDER);
            if (!userGroupProviderIdentifier.isSet()) {
                throw new AuthorizerCreationException("The user group provider must be specified.");
            }

            userGroupProvider = userGroupProviderLookup.getUserGroupProvider(userGroupProviderIdentifier.getValue());
            if (userGroupProvider == null) {
                throw new AuthorizerCreationException("Unable to locate user group provider with identifier " + userGroupProviderIdentifier.getValue());
            }
            logger.info("userGroupProvider : " + userGroupProvider.toString());

            // extract the identity mappings from nifi.properties if any are provided
            identityMappings = Collections.unmodifiableList(IdentityMappingUtil.getIdentityMappings(properties));
            groupMappings = Collections.unmodifiableList(IdentityMappingUtil.getGroupMappings(properties));

            // get the value of the initial admin identity
            final PropertyValue initialAdminIdentityProp = configurationContext.getProperty(PROP_INITIAL_ADMIN_IDENTITY);
            initialAdminIdentity = initialAdminIdentityProp.isSet() ? IdentityMappingUtil.mapIdentity(initialAdminIdentityProp.getValue(), identityMappings) : null;

            // extract any node identities
            nodeIdentities = new HashSet<>();
            for (Map.Entry<String,String> entry : configurationContext.getProperties().entrySet()) {
                Matcher matcher = NODE_IDENTITY_PATTERN.matcher(entry.getKey());
                if (matcher.matches() && !StringUtils.isBlank(entry.getValue())) {
                    final String mappedNodeIdentity = IdentityMappingUtil.mapIdentity(entry.getValue(), identityMappings);
                    nodeIdentities.add(mappedNodeIdentity);
                    logger.info("Added mapped node {} (raw node identity {})", new Object[]{mappedNodeIdentity, entry.getValue()});
                }
            }

            // read node group name
            PropertyValue nodeGroupNameProp = configurationContext.getProperty(PROP_NODE_GROUP_NAME);
            String nodeGroupName = (nodeGroupNameProp != null && nodeGroupNameProp.isSet()) ? nodeGroupNameProp.getValue() : null;

            // look up node group identifier using node group name
            nodeGroupIdentifier = null;

            if (nodeGroupName != null) {
                if (!StringUtils.isBlank(nodeGroupName)) {
                    logger.debug("Trying to load node group '{}' from the underlying userGroupProvider", nodeGroupName);
                    for (Group group : userGroupProvider.getGroups()) {
                        if (group.getName().equals(nodeGroupName)) {
                            nodeGroupIdentifier = group.getIdentifier();
                            break;
                        }
                    }

                    if (nodeGroupIdentifier == null) {
                        throw new AuthorizerCreationException(String.format(
                            "Authorizations node group '%s' could not be found", nodeGroupName));
                    }
                } else {
                    logger.debug("Empty node group name provided");
                }
            }
            // see if you have initial access policies
            // if not, generate
            final Set<AccessPolicy> policies = policyDataStore.getAccessPolicies();
            if(policies.size() == 0) {
                // load the initail access policies
                populateInitialAccessPolicies();
            }
        } catch (SAXException | AuthorizerCreationException | IllegalStateException e) {
            throw new AuthorizerCreationException(e);
        }
    }

    @Override
    public UserGroupProvider getUserGroupProvider() {
        logger.info("getUserGroupProvider() called.");
        return userGroupProvider;
    }

    @Override
    public Set<AccessPolicy> getAccessPolicies() throws AuthorizationAccessException {
        logger.debug("getAccessPolicies() called.");
        return policyDataStore.getAccessPolicies();
    }

    @Override
    public synchronized AccessPolicy addAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        logger.info("addAccessPolicy(AccessPolicy) called.");
        return policyDataStore.addAccessPolicy(accessPolicy);
    }


    @Override
    public AccessPolicy getAccessPolicy(String identifier) throws AuthorizationAccessException {
        logger.debug(String.format("getAccessPolicy called with identifier(%s)", identifier));
        if (identifier == null) {
            return null;
        }
        return policyDataStore.getAccessPolicy(identifier);
    }

    @Override
    public AccessPolicy getAccessPolicy(String resourceIdentifier, RequestAction action) throws AuthorizationAccessException {
        logger.debug(String.format("getAccessPolicy called with resourceIdentifier(%s) and action(%s)",resourceIdentifier,action.toString()) );
        return policyDataStore.getAccessPolicy(resourceIdentifier, action.toString());
    }

    @Override
    public synchronized AccessPolicy updateAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        logger.debug("updateAccessPolicy(accessPolicy) called.");
        if (accessPolicy == null) {
            throw new IllegalArgumentException("AccessPolicy cannot be null");
        }
        return policyDataStore.updateAccessPolicy(accessPolicy);
    }

    @Override
    public synchronized AccessPolicy deleteAccessPolicy(AccessPolicy accessPolicy) throws AuthorizationAccessException {
        logger.info("deleteAccessPolicy called.");
        if (accessPolicy == null) {
            throw new IllegalArgumentException("AccessPolicy cannot be null");
        }
        return policyDataStore.deleteAccessPolicy(accessPolicy);
    }

    @AuthorizerContext
    public void setNiFiProperties(NiFiProperties properties) {
        this.properties = properties;
    }

    @Override
    public synchronized void inheritFingerprint(String fingerprint) throws AuthorizationAccessException {
        logger.debug("inheritFingerprint called. MongoDBAccessPolicyProvider ignores inheritFingerprint.");
    }

    @Override
    public synchronized void forciblyInheritFingerprint(final String fingerprint) throws AuthorizationAccessException {
        logger.debug("forciblyInheritFingerprint called. MongoDBAccessPolicyProvider ignores forciblyInheritFingerprint.");
    }

    @Override
    public void checkInheritability(String proposedFingerprint) throws AuthorizationAccessException, UninheritableAuthorizationsException {
        logger.debug("checkInheritability called. MongoDBAccessPolicyProvider ignores checkInheritability.");
    }

    @Override
    public String getFingerprint() throws AuthorizationAccessException {
        logger.debug("getFingerprint called. MongoDBAccessPolicyProvider returns null");
        return null;
    }

    /**
     * This method generates and populate the inital access config
     *
     */
    private void populateInitialAccessPolicies() throws SAXException {
        // connect data source and retrieve AccessPolicy list
        final Set<AccessPolicy> policiesInMemory = new HashSet<>();
        final boolean hasInitialAdminIdentity = (initialAdminIdentity != null && !StringUtils.isBlank(initialAdminIdentity));

        parseFlow();
        if (hasInitialAdminIdentity) {
            logger.debug("Populating authorizations for Initial Admin: " + initialAdminIdentity);
            populateInitialAdmin(policiesInMemory);
        }
        populateNodes(policiesInMemory);

        // save the initial access policies to db
        for(AccessPolicy apolicy: policiesInMemory){
            policyDataStore.addInitialAccessPolicyConfig(apolicy);
        }

    }

    /**
     * Try to parse the flow configuration file to extract the root group id and port information.
     *
     * @throws SAXException if an error occurs creating the schema
     */
    private void parseFlow() throws SAXException {
        logger.debug("parseFlow called.");

        final FlowParser flowParser = new FlowParser();
        final FlowInfo flowInfo = flowParser.parse(properties.getFlowConfigurationFile());

        if (flowInfo != null) {
            rootGroupId = flowInfo.getRootGroupId();
            ports = flowInfo.getPorts() == null ? new ArrayList<>() : flowInfo.getPorts();
        }
        logger.debug("parseFlow ended.");
    }

    /**
     *  Creates the initial admin user and policies for access the flow and managing users and policies.
     * @param inMemoryAccessPolicies the AccessPolicies to be committed to DB
     */
    private void populateInitialAdmin(Set<AccessPolicy> inMemoryAccessPolicies) {
        final User initialAdmin = userGroupProvider.getUserByIdentity(initialAdminIdentity);
        if (initialAdmin == null) {
            throw new AuthorizerCreationException("Unable to locate initial admin " + initialAdminIdentity + " to seed policies");
        }

        // grant the user read access to the /flow resource
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Flow.getValue(), initialAdmin.getIdentifier(), READ_CODE);

        // grant the user read access to the root process group resource
        if (rootGroupId != null) {
            addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Data.getValue() + ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, initialAdmin.getIdentifier(), READ_CODE);
            addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Data.getValue() + ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, initialAdmin.getIdentifier(), WRITE_CODE);

            addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, initialAdmin.getIdentifier(), READ_CODE);
            addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, initialAdmin.getIdentifier(), WRITE_CODE);
        }

        // grant the user write to restricted components
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.RestrictedComponents.getValue(), initialAdmin.getIdentifier(), WRITE_CODE);

        // grant the user read/write access to the /tenants resource
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Tenant.getValue(), initialAdmin.getIdentifier(), READ_CODE);
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Tenant.getValue(), initialAdmin.getIdentifier(), WRITE_CODE);

        // grant the user read/write access to the /policies resource
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Policy.getValue(), initialAdmin.getIdentifier(), READ_CODE);
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Policy.getValue(), initialAdmin.getIdentifier(), WRITE_CODE);

        // grant the user read/write access to the /controller resource
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Controller.getValue(), initialAdmin.getIdentifier(), READ_CODE);
        addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Controller.getValue(), initialAdmin.getIdentifier(), WRITE_CODE);
    }

    /**
     * Creates a user for each node and gives the nodes write permission to /proxy.
     * @param inMemoryAccessPolicies the AccessPolicies to be committed to DB
     */
    private void populateNodes(Set<AccessPolicy> inMemoryAccessPolicies) {
        // authorize static nodes
        for (String nodeIdentity : nodeIdentities) {
            final User node = userGroupProvider.getUserByIdentity(nodeIdentity);
            if (node == null) {
                throw new AuthorizerCreationException("Unable to locate node " + nodeIdentity + " to seed policies.");
            }
            logger.debug("Populating default authorizations for node '{}' ({})", node.getIdentity(), node.getIdentifier());
            // grant access to the proxy resource
            addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Proxy.getValue(), node.getIdentifier(), WRITE_CODE);

            // grant the user read/write access data of the root group
            if (rootGroupId != null) {
                addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Data.getValue() + ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, node.getIdentifier(), READ_CODE);
                addUserToAccessPolicy(inMemoryAccessPolicies, ResourceType.Data.getValue() + ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, node.getIdentifier(), WRITE_CODE);
            }
        }

        // authorize dynamic nodes (node group)
        if (nodeGroupIdentifier != null) {
            logger.debug("Populating default authorizations for group '{}' ({})", userGroupProvider.getGroup(nodeGroupIdentifier).getName(), nodeGroupIdentifier);
            addGroupToAccessPolicy(inMemoryAccessPolicies, ResourceType.Proxy.getValue(), nodeGroupIdentifier, WRITE_CODE);

            if (rootGroupId != null) {
                addGroupToAccessPolicy(inMemoryAccessPolicies, ResourceType.Data.getValue() + ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, nodeGroupIdentifier, READ_CODE);
                addGroupToAccessPolicy(inMemoryAccessPolicies, ResourceType.Data.getValue() + ResourceType.ProcessGroup.getValue() + "/" + rootGroupId, nodeGroupIdentifier, WRITE_CODE);
            }
        }
    }

    /**
     * Creates and adds an access policy for the given resource, identity, and actions to the specified authorizations.
     *
     * @param inMemoryAccessPolicies the AccessPolicies to be committed to DB
     * @param resource the resource for the policy
     * @param userIdentifier the identifier for the user to add to the policy
     * @param action the action for the policy
     */
    private void addUserToAccessPolicy(Set<AccessPolicy> inMemoryAccessPolicies, final String resource, final String userIdentifier, final RequestAction action) {
        // first try to find an existing policy for the given resource and action
        AccessPolicy foundPolicy =null;
        for (AccessPolicy policy : inMemoryAccessPolicies) {
            if (policy.getResource().equals(resource) && policy.getAction().equals(action)) {
                foundPolicy = policy;
                break;
            }
        }

        if (foundPolicy == null) {
            // if we didn't find an existing policy create a new one
            final String uuidSeed = resource + action;

            final AccessPolicy.Builder builder = new AccessPolicy.Builder()
                    .identifierGenerateFromSeed(uuidSeed)
                    .resource(resource)
                    .addUser(userIdentifier)
                    .action(action);

            final AccessPolicy accessPolicy = builder.build();
            inMemoryAccessPolicies.add(accessPolicy);

        } else {
            // otherwise add the user to the existing policy
            // since users and group set of an access policy object is immutable,
            // create a new acess policy object
            final AccessPolicy.Builder builder = new AccessPolicy.Builder(foundPolicy)
                    .addUser(userIdentifier);
            final AccessPolicy updatedPolicy = builder.build();
            inMemoryAccessPolicies.remove(foundPolicy);
            inMemoryAccessPolicies.add(updatedPolicy);
        }
    }

    /**
     * Creates and adds an access policy for the given resource, group identity, and actions to the specified authorizations.
     *
     * @param inMemoryAccessPolicies the AccessPolicies to be committed to DB
     * @param resource       the resource for the policy
     * @param groupIdentifier the identifier for the group to add to the policy
     * @param action         the action for the policy
     */
    private void addGroupToAccessPolicy(Set<AccessPolicy> inMemoryAccessPolicies, final String resource, final String groupIdentifier, final RequestAction action) {
        // first try to find an existing policy for the given resource and action
        AccessPolicy foundPolicy = null;
        for (AccessPolicy policy : inMemoryAccessPolicies) {
            if (policy.getResource().equals(resource) && policy.getAction().equals(action)) {
                foundPolicy = policy;
                break;
            }
        }

        if (foundPolicy == null) {
            // if we didn't find an existing policy create a new one
            final String uuidSeed = resource + action;

            final AccessPolicy.Builder builder = new AccessPolicy.Builder()
                    .identifierGenerateFromSeed(uuidSeed)
                    .resource(resource)
                    .addGroup(groupIdentifier)
                    .action(action);

            final AccessPolicy accessPolicy = builder.build();
            inMemoryAccessPolicies.add(accessPolicy);
        } else {
            // otherwise add the user to the existing policy
            // since users and group set of an access policy object is immutable,
            // create a new acess policy object
            final AccessPolicy.Builder builder = new AccessPolicy.Builder(foundPolicy)
                    .addGroup(groupIdentifier);
            final AccessPolicy updatedPolicy = builder.build();
            inMemoryAccessPolicies.remove(foundPolicy);
            inMemoryAccessPolicies.add(updatedPolicy);
        }
    }

    @Override
    public void preDestruction() throws AuthorizerDestructionException {
    }
}