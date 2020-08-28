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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;

import org.apache.nifi.attribute.expression.language.StandardPropertyValue;
import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.AccessPolicyProviderInitializationContext;
import org.apache.nifi.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.authorization.FileUserGroupProvider;
import org.apache.nifi.authorization.RequestAction;
import org.apache.nifi.authorization.User;
import org.apache.nifi.authorization.UserGroupProvider;
import org.apache.nifi.authorization.UserGroupProviderLookup;
import org.apache.nifi.authorization.resource.ResourceType;
import org.apache.nifi.authorization.azure.model.Policy;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.parameter.ParameterLookup;
import org.apache.nifi.util.MockPropertyValue;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.util.file.FileUtils;
import org.bson.Document;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MongoDBAccessPolicyProviderIT {
    private static final Logger logger = LoggerFactory.getLogger(MongoDBAccessPolicyProviderIT.class);

    private static final Properties CONFIG;

    private static final String CREDENTIALS_FILE = System.getProperty("user.home") + "/azure-accesspolicyprovider.PROPERTIES";

    static {
        CONFIG = new Properties();
        try {
            final FileInputStream fis = new FileInputStream(CREDENTIALS_FILE);
            try {
                CONFIG.load(fis);
            } catch (IOException e) {
                fail("Could not open credentials file " + CREDENTIALS_FILE + ": " + e.getLocalizedMessage());
            } finally {
                FileUtils.closeQuietly(fis);
            }
        } catch (FileNotFoundException e) {
            fail("Could not open credentials file " + CREDENTIALS_FILE + ": " + e.getLocalizedMessage());
        }
    }

    protected static String getConnectionString() {
        return CONFIG.getProperty("ConnectionString");
    }
    protected static String getDBName() {
        return CONFIG.getProperty("DBName");
    }

    private static final String EMPTY_TENANTS_CONCISE =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        + "<tenants/>";

    private static final String TENANTS =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
        "<tenants>" +
        "  <groups>" +
        "    <group identifier=\"group-1\" name=\"group-1\">" +
        "       <user identifier=\"user-1\" />" +
        "    </group>" +
        "    <group identifier=\"group-2\" name=\"group-2\">" +
        "       <user identifier=\"user-2\" />" +
        "    </group>" +
        "  </groups>" +
        "  <users>" +
        "    <user identifier=\"user-1\" identity=\"user-1\" />" +
        "    <user identifier=\"user-2\" identity=\"user-2\" />" +
        "  </users>" +
        "</tenants>";

    private static final String TENANTS_FOR_ADMIN_AND_NODES =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<tenants>" +
            "  <users>" +
            "    <user identifier=\"admin-user\" identity=\"admin-user\"/>" +
            "    <user identifier=\"node1\" identity=\"node1\"/>" +
            "    <user identifier=\"node2\" identity=\"node2\"/>" +
            "  </users>" +
            "</tenants>";

    private static final String TENANTS_FOR_ADMIN_AND_NODE_GROUP =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<tenants>" +
                "  <groups>" +
                "    <group identifier=\"cluster-nodes\" name=\"Cluster Nodes\">" +
                "       <user identifier=\"node1\" />" +
                "       <user identifier=\"node2\" />" +
                "    </group>" +
                "  </groups>" +
                "  <users>" +
                "    <user identifier=\"admin-user\" identity=\"admin-user\"/>" +
                "    <user identifier=\"node1\" identity=\"node1\"/>" +
                "    <user identifier=\"node2\" identity=\"node2\"/>" +
                "  </users>" +
                "</tenants>";

    private AuthorizerConfigurationContext configurationContext;
    static final String PROP_INITIAL_USER_IDENTITY_PREFIX = "Initial User Identity ";
    static final String PROP_TENANTS_FILE = "Users File";
    static final String PROP_LEGACY_AUTHORIZED_USERS_FILE = "Legacy Authorized Users File";

    // This is the root group id from the flow.xml.gz in src/test/resources
    private static final String ROOT_GROUP_ID = "e530e14c-adcf-41c2-b5d6-d9a59ba8765c";

    private NiFiProperties properties;
    private MongoDBAccessPolicyProvider accessPolicyProvider;
    private FileUserGroupProvider userGroupProvider;
    private File primaryTenants;
    private File flow;
    private File flowNoPorts;
    private File flowWithDns;

    @Before
    public void setup() throws IOException {
        // primary tenants
        primaryTenants = new File("target/authorizations/users.xml");
        FileUtils.ensureDirectoryExistAndCanAccess(primaryTenants.getParentFile());


        flow = new File("src/test/resources/flow.xml.gz");
        FileUtils.ensureDirectoryExistAndCanAccess(flow.getParentFile());

        flowNoPorts = new File("src/test/resources/flow-no-ports.xml.gz");
        FileUtils.ensureDirectoryExistAndCanAccess(flowNoPorts.getParentFile());

        flowWithDns = new File("src/test/resources/flow-with-dns.xml.gz");
        FileUtils.ensureDirectoryExistAndCanAccess(flowWithDns.getParentFile());

        properties = mock(NiFiProperties.class);
        when(properties.getFlowConfigurationFile()).thenReturn(flow);

        userGroupProvider = new FileUserGroupProvider();
        userGroupProvider.setNiFiProperties(properties);
        userGroupProvider.initialize(null);


        configurationContext = mock(AuthorizerConfigurationContext.class);

        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_MONGODB_CONNECTION_STR)))
            .thenReturn(new MockPropertyValue(getConnectionString()));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_MONGODB_DB_NAME)))
            .thenReturn(new MockPropertyValue(getDBName()));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
            .thenReturn(new StandardPropertyValue(null, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_USER_GROUP_PROVIDER)))
            .thenReturn(new StandardPropertyValue("user-group-provider", null, ParameterLookup.EMPTY));

        when(configurationContext.getProperty(eq(PROP_TENANTS_FILE)))
            .thenReturn(new StandardPropertyValue(primaryTenants.getPath(), null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(PROP_LEGACY_AUTHORIZED_USERS_FILE)))
            .thenReturn(new StandardPropertyValue(null, null, ParameterLookup.EMPTY));


        when(configurationContext.getProperties()).then((invocation) -> {
            final Map<String, String> properties = new HashMap<>();

            final PropertyValue tenantFile = configurationContext.getProperty(PROP_TENANTS_FILE);
            if (tenantFile != null) {
                properties.put(PROP_TENANTS_FILE, tenantFile.getValue());
            }

            final PropertyValue initialAdmin = configurationContext.getProperty(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY);
            if (initialAdmin != null) {
                properties.put(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY, initialAdmin.getValue());
            }
            final PropertyValue legacyAuthFile = configurationContext.getProperty(PROP_LEGACY_AUTHORIZED_USERS_FILE);
            if (legacyAuthFile != null) {
                properties.put(PROP_LEGACY_AUTHORIZED_USERS_FILE, legacyAuthFile.getValue());
            }

            int i = 1;
            while (true) {
                final String key = MongoDBAccessPolicyProvider.PROP_NODE_IDENTITY_PREFIX + i++;
                final PropertyValue value = configurationContext.getProperty(key);
                if (value == null) {
                    break;
                } else {
                    properties.put(key, value.getValue());
                }
            }

            i = 1;
            while (true) {
                final String key = PROP_INITIAL_USER_IDENTITY_PREFIX + i++;
                final PropertyValue value = configurationContext.getProperty(key);
                if (value == null) {
                    break;
                } else {
                    properties.put(key, value.getValue());
                }
            }

            // ensure the initial admin is seeded into the user provider if appropriate
            if (properties.containsKey(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)) {
                i = 0;
                while (true) {
                    final String key = PROP_INITIAL_USER_IDENTITY_PREFIX + i++;
                    if (!properties.containsKey(key)) {
                        properties.put(key, properties.get(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY));
                        break;
                    }
                }
            }
            return properties;
        });
        final AccessPolicyProviderInitializationContext initializationContext = mock(AccessPolicyProviderInitializationContext.class);
        when(initializationContext.getUserGroupProviderLookup()).thenReturn(new UserGroupProviderLookup() {
            @Override
            public UserGroupProvider getUserGroupProvider(String identifier) {
                return userGroupProvider;
            }
        });

        // setup test db
        setupTestDBandCollection();

        accessPolicyProvider = new MongoDBAccessPolicyProvider();
        accessPolicyProvider.setNiFiProperties(properties);
        accessPolicyProvider.initialize(initializationContext);

    }
    private MongoClient mongoClient;
    private MongoDatabase mongoDB;

    private void setupTestDBandCollection(){
        mongoClient = new MongoClient(new MongoClientURI(getConnectionString()));
        mongoDB = mongoClient.getDatabase(getDBName());

        MongoIterable<String> collections =  mongoDB.listCollectionNames();
        boolean collection_exists = false;
        for(String collection: collections){
            if(collection.equals(Policy.ENTITY_COLLECTION_NAME)){
                collection_exists = true;
            }
        }
        if(!collection_exists){
            mongoDB.createCollection(Policy.ENTITY_COLLECTION_NAME);
        }
    }

    @AfterClass
    public static void dropTestDBAndContainer() {

    }

    @After
    public void dropTestData() {
        deleteFile(primaryTenants);
        mongoDB.getCollection(Policy.ENTITY_COLLECTION_NAME)
            .deleteMany(new Document());

    }

    @Test
    public void testOnConfiguredWhenInitialAdminProvided() throws Exception {
        final String adminIdentity = "admin-user";

        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));

        writeFile(primaryTenants, EMPTY_TENANTS_CONCISE);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        final Set<User> users = userGroupProvider.getUsers();
        final User adminUser = users.iterator().next();
        assertEquals(adminIdentity, adminUser.getIdentity());

        final Set<AccessPolicy> policies = accessPolicyProvider.getAccessPolicies();
        assertEquals(12, policies.size());

        final String rootGroupResource = ResourceType.ProcessGroup.getValue() + "/" + ROOT_GROUP_ID;

        boolean foundRootGroupPolicy = false;
        for (AccessPolicy policy : policies) {
            if (policy.getResource().equals(rootGroupResource)) {
                foundRootGroupPolicy = true;
                break;
            }
        }

        assertTrue(foundRootGroupPolicy);
    }
    @Test
    public void testOnConfiguredWhenInitialAdminProvidedWithIdentityMapping() throws Exception {
        final Properties props = new Properties();
        props.setProperty("nifi.security.identity.mapping.pattern.dn1", "^CN=(.*?), OU=(.*?), O=(.*?), L=(.*?), ST=(.*?), C=(.*?)$");
        props.setProperty("nifi.security.identity.mapping.value.dn1", "$1_$2_$3");

        properties = getNiFiProperties(props);
        when(properties.getFlowConfigurationFile()).thenReturn(flow);

        userGroupProvider.setNiFiProperties(properties);
        accessPolicyProvider.setNiFiProperties(properties);

        final String adminIdentity = "CN=localhost, OU=Apache NiFi, O=Apache, L=Santa Monica, ST=CA, C=US";
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));

        writeFile(primaryTenants, EMPTY_TENANTS_CONCISE);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);
        final Set<User> users = userGroupProvider.getUsers();
        final User adminUser = users.iterator().next();

        assertEquals("localhost_Apache NiFi_Apache", adminUser.getIdentity());
    }

    @Test
    public void testOnConfiguredWhenNodeIdentitiesProvided() throws Exception {
        final String adminIdentity = "admin-user";
        final String nodeIdentity1 = "node1";
        final String nodeIdentity2 = "node2";

        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_NODE_IDENTITY_PREFIX + "1")))
                .thenReturn(new StandardPropertyValue(nodeIdentity1, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_NODE_IDENTITY_PREFIX + "2")))
                .thenReturn(new StandardPropertyValue(nodeIdentity2, null, ParameterLookup.EMPTY));

        when(configurationContext.getProperty(eq(PROP_INITIAL_USER_IDENTITY_PREFIX + "1")))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(PROP_INITIAL_USER_IDENTITY_PREFIX + "2")))
                .thenReturn(new StandardPropertyValue(nodeIdentity1, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(PROP_INITIAL_USER_IDENTITY_PREFIX + "3")))
                .thenReturn(new StandardPropertyValue(nodeIdentity2, null, ParameterLookup.EMPTY));

        writeFile(primaryTenants, EMPTY_TENANTS_CONCISE);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        User nodeUser1 = userGroupProvider.getUserByIdentity(nodeIdentity1);
        User nodeUser2 = userGroupProvider.getUserByIdentity(nodeIdentity2);

        AccessPolicy proxyWritePolicy = accessPolicyProvider.getAccessPolicy(ResourceType.Proxy.getValue(), RequestAction.WRITE);

        assertNotNull(proxyWritePolicy);
        assertTrue(proxyWritePolicy.getUsers().contains(nodeUser1.getIdentifier()));
        assertTrue(proxyWritePolicy.getUsers().contains(nodeUser2.getIdentifier()));
    }

    @Test
    public void testOnConfiguredWhenNodeIdentitiesProvidedAndUsersAlreadyExist() throws Exception {

        final String adminIdentity = "admin-user";
        final String nodeIdentity1 = "node1";
        final String nodeIdentity2 = "node2";

        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_NODE_IDENTITY_PREFIX + "1")))
                .thenReturn(new StandardPropertyValue(nodeIdentity1, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_NODE_IDENTITY_PREFIX + "2")))
                .thenReturn(new StandardPropertyValue(nodeIdentity2, null, ParameterLookup.EMPTY));

        when(configurationContext.getProperty(eq(PROP_INITIAL_USER_IDENTITY_PREFIX + "1")))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(PROP_INITIAL_USER_IDENTITY_PREFIX + "2")))
                .thenReturn(new StandardPropertyValue(nodeIdentity1, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(PROP_INITIAL_USER_IDENTITY_PREFIX + "3")))
                .thenReturn(new StandardPropertyValue(nodeIdentity2, null, ParameterLookup.EMPTY));

        writeFile(primaryTenants, TENANTS_FOR_ADMIN_AND_NODES);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        User nodeUser1 = userGroupProvider.getUserByIdentity(nodeIdentity1);
        User nodeUser2 = userGroupProvider.getUserByIdentity(nodeIdentity2);

        AccessPolicy proxyWritePolicy = accessPolicyProvider.getAccessPolicy(ResourceType.Proxy.getValue(), RequestAction.WRITE);

        assertNotNull(proxyWritePolicy);
        assertTrue(proxyWritePolicy.getUsers().contains(nodeUser1.getIdentifier()));
        assertTrue(proxyWritePolicy.getUsers().contains(nodeUser2.getIdentifier()));
    }

    @Test
    public void testOnConfiguredWhenNodeGroupProvided() throws Exception {
        final String adminIdentity = "admin-user";
        final String nodeGroupName = "Cluster Nodes";
        final String nodeGroupIdentifier = "cluster-nodes";
        final String nodeIdentity1 = "node1";
        final String nodeIdentity2 = "node2";

        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
                .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_NODE_GROUP_NAME)))
                .thenReturn(new StandardPropertyValue(nodeGroupName, null, ParameterLookup.EMPTY));

        writeFile(primaryTenants, TENANTS_FOR_ADMIN_AND_NODE_GROUP);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        assertNotNull(userGroupProvider.getUserByIdentity(nodeIdentity1));
        assertNotNull(userGroupProvider.getUserByIdentity(nodeIdentity2));

        AccessPolicy proxyWritePolicy = accessPolicyProvider.getAccessPolicy(ResourceType.Proxy.getValue(), RequestAction.WRITE);

        assertNotNull(proxyWritePolicy);
        assertTrue(proxyWritePolicy.getGroups().contains(nodeGroupIdentifier));
    }

    @Test
    public void testOnConfiguredWhenNodeGroupEmpty() throws Exception {
        final String adminIdentity = "admin-user";

        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_INITIAL_ADMIN_IDENTITY)))
            .thenReturn(new StandardPropertyValue(adminIdentity, null, ParameterLookup.EMPTY));
        when(configurationContext.getProperty(eq(MongoDBAccessPolicyProvider.PROP_NODE_GROUP_NAME)))
            .thenReturn(new StandardPropertyValue("", null, ParameterLookup.EMPTY));

        writeFile(primaryTenants, TENANTS_FOR_ADMIN_AND_NODE_GROUP);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        assertNull(accessPolicyProvider.getAccessPolicy(ResourceType.Proxy.getValue(), RequestAction.WRITE));
    }


    @Test
    public void testAddAccessPolicy() throws Exception {
        writeFile(primaryTenants, TENANTS);
        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        assertEquals(0, accessPolicyProvider.getAccessPolicies().size());

        final AccessPolicy policy1 = new AccessPolicy.Builder()
                .identifier("policy-1")
                .resource("resource-1")
                .addUser("user-1")
                .addGroup("group-1")
                .action(RequestAction.READ)
                .build();

        accessPolicyProvider.addAccessPolicy(policy1);
        Set<AccessPolicy> policies = accessPolicyProvider.getAccessPolicies();
        assertEquals(1, policies.size());
        final AccessPolicy returnedPolicy1 = (AccessPolicy) policies.toArray()[0] ;
        assertEquals(policy1.getIdentifier(), returnedPolicy1.getIdentifier());
        assertEquals(policy1.getResource(), returnedPolicy1.getResource());
        assertEquals(policy1.getUsers(), returnedPolicy1.getUsers());
        assertEquals(policy1.getGroups(), returnedPolicy1.getGroups());
        assertEquals(policy1.getAction(), returnedPolicy1.getAction());
    }

    @Test
    public void testAddAccessPolicyWithEmptyUsersAndGroups() throws Exception {
        writeFile(primaryTenants, TENANTS);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        assertEquals(0, accessPolicyProvider.getAccessPolicies().size());

        final AccessPolicy policy1 = new AccessPolicy.Builder()
                .identifier("policy-1")
                .resource("resource-1")
                .action(RequestAction.READ)
                .build();

        accessPolicyProvider.addAccessPolicy(policy1);
        Set<AccessPolicy> policies = accessPolicyProvider.getAccessPolicies();
        assertEquals(1, policies.size());
        final AccessPolicy returnedPolicy1 = (AccessPolicy) policies.toArray()[0] ;
        assertEquals(policy1.getIdentifier(), returnedPolicy1.getIdentifier());
        assertEquals(policy1.getResource(), returnedPolicy1.getResource());
        assertEquals(policy1.getUsers(), returnedPolicy1.getUsers());
        assertEquals(policy1.getGroups(), returnedPolicy1.getGroups());
        assertEquals(policy1.getAction(), returnedPolicy1.getAction());
    }

    @Test
    public void testUpdatePolicy() throws Exception {

        writeFile(primaryTenants, TENANTS);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        assertEquals(0, accessPolicyProvider.getAccessPolicies().size());

        final AccessPolicy.Builder builder = new AccessPolicy.Builder()
                .identifier("policy-1")
                .resource("resource-A")
                .addUser("user-1")
                .action(RequestAction.READ);

        final AccessPolicy originalPolicy = builder.build();
        accessPolicyProvider.addAccessPolicy(originalPolicy);
        AccessPolicy queryResult = accessPolicyProvider.getAccessPolicy("policy-1");
        assertTrue(queryResult.getUsers().size() == 1);
        assertTrue(queryResult.getGroups().size() == 0);

        final AccessPolicy updatedpolicy = builder.addGroup("group-1").build();

        accessPolicyProvider.updateAccessPolicy(updatedpolicy);

        queryResult = accessPolicyProvider.getAccessPolicy("policy-1");
        assertTrue(queryResult.getUsers().size() == 1);
        assertTrue(queryResult.getGroups().size() == 1);

    }

    @Test
    public void testDeleteAccessPolicy() throws Exception {

        writeFile(primaryTenants, TENANTS);

        userGroupProvider.onConfigured(configurationContext);
        accessPolicyProvider.onConfigured(configurationContext);

        assertEquals(0, accessPolicyProvider.getAccessPolicies().size());

        final AccessPolicy policy = new AccessPolicy.Builder()
                .identifier("policy-1")
                .resource("resource-A")
                .addUser("user-A")
                .addGroup("group-A")
                .action(RequestAction.READ)
                .build();
        accessPolicyProvider.addAccessPolicy(policy);
        AccessPolicy queryResult = accessPolicyProvider.getAccessPolicy("policy-1");
        assertNotNull(queryResult);
        accessPolicyProvider.deleteAccessPolicy(policy);

        queryResult = accessPolicyProvider.getAccessPolicy("policy-1");
        assertNull(queryResult);

    }

    private static void writeFile(final File file, final String content) throws Exception {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        try (final FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(bytes);
        }
    }

    private static boolean deleteFile(final File file) {
        if (file.isDirectory()) {
            FileUtils.deleteFilesInDir(file, null, null, true, true);
        }
        return FileUtils.deleteFile(file, null, 10);
    }

    private NiFiProperties getNiFiProperties(final Properties properties) {
        final NiFiProperties nifiProperties = Mockito.mock(NiFiProperties.class);
        when(nifiProperties.getPropertyKeys()).thenReturn(properties.stringPropertyNames());

        when(nifiProperties.getProperty(anyString())).then(new Answer<String>() {
            @Override
            public String answer(InvocationOnMock invocationOnMock) throws Throwable {
                return properties.getProperty((String)invocationOnMock.getArguments()[0]);
            }
        });
        return nifiProperties;
    }
}