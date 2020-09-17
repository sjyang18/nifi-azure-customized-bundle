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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.curator.RetryPolicy;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.api.ACLProvider;
import org.apache.curator.framework.imps.DefaultACLProvider;
import org.apache.curator.framework.recipes.leader.LeaderSelector;
import org.apache.curator.framework.recipes.leader.LeaderSelectorListener;
import org.apache.curator.framework.recipes.leader.Participant;
import org.apache.curator.framework.state.ConnectionState;
import org.apache.curator.retry.RetryNTimes;
import org.apache.curator.shaded.com.google.common.collect.Lists;
import org.apache.curator.utils.PathUtils;
import org.apache.nifi.util.NiFiProperties;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class NiFiLeaderFinder {
    private String zkConnectionString;
    private String rootPath;
    private String authType;
    private String authPrincipal;
    private String removeHostFromPrincipal;
    private String removeRealmFromPrincipal;


    private static final Logger logger = LoggerFactory.getLogger(NiFiLeaderFinder.class);
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    private static final Pattern PORT_PATTERN = Pattern.compile("[0-9]{1,5}");

    public static final String PRIMARY_NODE = "Primary Node";
    public static final String CLUSTER_COORDINATOR = "Cluster Coordinator";
    public static final String SASL_AUTH_SCHEME="sasl";
    private Map<String, String> cache = new HashMap<>();

    public NiFiLeaderFinder(String zkConnectionString, String rootPath) {
        this.zkConnectionString = zkConnectionString;
        this.rootPath = rootPath;
    }

    /**
     * Takes a given connect string and splits it by ',' character. For each
     * split result trims whitespace then splits by ':' character. For each
     * secondary split if a single value is returned it is trimmed and then the
     * default zookeeper 2181 is append by adding ":2181". If two values are
     * returned then the second value is evaluated to ensure it contains only
     * digits and if not then the entry is in error and exception is raised.
     * If more than two values are
     * returned the entry is in error and an exception is raised.
     * Each entry is trimmed and if empty the
     * entry is skipped. After all splits are cleaned then they are all appended
     * back together demarcated by "," and the full string is returned.
     *
     * @param connectString the string to clean
     * @return cleaned connect string guaranteed to be non null but could be
     * empty
     */
    private static String cleanConnectString(final String connectString) {
        final String nospaces = StringUtils.deleteWhitespace(connectString);
        final String hostPortPairs[] = StringUtils.split(nospaces, ",", 100);
        final List<String> cleanedEntries = new ArrayList<>(hostPortPairs.length);
        for (final String pair : hostPortPairs) {
            final String pairSplits[] = StringUtils.split(pair, ":", 3);
            if (pairSplits.length > 2 || pairSplits[0].isEmpty()) {
                logger.error("Invalid host:port pair entry '" +
                        pair + "' in nifi.properties " + NiFiProperties.ZOOKEEPER_CONNECT_STRING + "' property");
            }
            if (pairSplits.length == 1) {
                cleanedEntries.add(pairSplits[0] + ":2181");
            }else{
                if(PORT_PATTERN.matcher(pairSplits[1]).matches()){
                    cleanedEntries.add(pairSplits[0] + ":" + pairSplits[1]);
                }else{
                    logger.error("The port specified in this pair must be 1 to 5 digits only but was '" +
                        pair + "' in nifi.properties " + NiFiProperties.ZOOKEEPER_CONNECT_STRING + "' property");
                }
            }
        }
        return StringUtils.join(cleanedEntries, ",");
    }

    /**
     * Factory method that creates an instance of NifiLeaderFinder from NiFiProperties
     * @param nifiProperties
     * @return NifiLeaderFinder instance
     */    
    public static NiFiLeaderFinder create(final NiFiProperties nifiProperties) {
        final String connectString = nifiProperties.getProperty(NiFiProperties.ZOOKEEPER_CONNECT_STRING);
        if (connectString == null || connectString.trim().isEmpty()) {
            throw new IllegalStateException("The '" + NiFiProperties.ZOOKEEPER_CONNECT_STRING + "' property is not set in nifi.properties");
        }
        final String cleanedConnectString = cleanConnectString(connectString);
        if (cleanedConnectString.isEmpty()) {
            throw new IllegalStateException("The '" + NiFiProperties.ZOOKEEPER_CONNECT_STRING +
                    "' property is set in nifi.properties but needs to be in pairs of host:port separated by commas");
        }

        final String rootPath = nifiProperties.getProperty(NiFiProperties.ZOOKEEPER_ROOT_NODE, NiFiProperties.DEFAULT_ZOOKEEPER_ROOT_NODE);
        final String authType = nifiProperties.getProperty(NiFiProperties.ZOOKEEPER_AUTH_TYPE,NiFiProperties.DEFAULT_ZOOKEEPER_AUTH_TYPE);
        final String authPrincipal = nifiProperties.getKerberosServicePrincipal();
        final String removeHostFromPrincipal = nifiProperties.getProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_HOST_FROM_PRINCIPAL,
                NiFiProperties.DEFAULT_ZOOKEEPER_KERBEROS_REMOVE_HOST_FROM_PRINCIPAL);
        final String removeRealmFromPrincipal = nifiProperties.getProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_REALM_FROM_PRINCIPAL,
                NiFiProperties.DEFAULT_ZOOKEEPER_KERBEROS_REMOVE_REALM_FROM_PRINCIPAL);
        try {
            PathUtils.validatePath(rootPath);
        } catch (final IllegalArgumentException e) {
            throw new IllegalArgumentException("The '" + NiFiProperties.ZOOKEEPER_ROOT_NODE + "' property in nifi.properties is set to an illegal value: " + rootPath);
        }

        return new Builder()
                    .setZkConnectionString(cleanedConnectString)
                    .setRootPath(rootPath)
                    .setAuthType(authType)
                    .setAuthPrincipal(authPrincipal)
                    .setRemoveHostFromPrincipal(removeHostFromPrincipal)
                    .setRemoveRealmFromPrincipal(removeRealmFromPrincipal)
                    .build();
    }


    protected CuratorFramework createClient() {
        final RetryPolicy retryPolicy = new RetryNTimes(1, 100);
        ACLProvider aclProvider = StringUtils.equalsIgnoreCase(authType, SASL_AUTH_SCHEME) ? new SaslACLProvider() : new DefaultACLProvider();

        final CuratorFramework client = CuratorFrameworkFactory.builder()
            .connectString(zkConnectionString)
            .retryPolicy(retryPolicy)
            .aclProvider(aclProvider)
            .defaultData(new byte[0])
            .build();

        client.start();
        return client;
    }

    private String getElectionPath(final String roleName) {
        final String leaderPath = rootPath + (rootPath.endsWith("/") ? "" : "/") + "leaders/" + roleName;
        return leaderPath;
    }

    /**
     * Run query to Zookeeper in a NiFi Cluster and find the leader
     * @param roleName (either 'Primary Node' or 'Cluster Coordinator' in NiFi Cluster)
     * @return nodeName in the form of hostname:port
     */
    public String findLeader(final String roleName) {

        try (CuratorFramework client = createClient()) {
            final LeaderSelectorListener electionListener = new LeaderSelectorListener() {
                @Override
                public void stateChanged(CuratorFramework client, ConnectionState newState) {
                }

                @Override
                public void takeLeadership(CuratorFramework client) throws Exception {
                }
            };

            final String electionPath = getElectionPath(roleName);

            try {
                LeaderSelector selector = new LeaderSelector(client, electionPath, electionListener);
                final Participant leader = selector.getLeader();
                final String nodeAndPort = leader == null ? null : leader.getId();
                logger.debug(String.format("returning nodeAndPort: %s", nodeAndPort));
                return nodeAndPort;
            } catch (final KeeperException.NoNodeException nne) {
                // If there is no ZNode, then there is no elected leader.
                logger.debug("If there is no ZNode, then there is no elected leader.");
                return null;
            } catch (final Exception e) {
                logger.warn(e.getMessage());
                return null;
            }
        } finally {
        }
    }

    /**
     * Schedules the task of refreshCache() method and keep the primary and coordinate node in cache
     */
    public void scheduleToCachePrimaryAndCoordinateNode(long fixedDelayInSeconds) {
        refreshCache(); 
        scheduler.scheduleWithFixedDelay(() -> {
            try {
                logger.info("scheduling refreshCache()");
                refreshCache(); 
            } catch (final Throwable t) {
                logger.error("", t);
            }
        }, fixedDelayInSeconds, fixedDelayInSeconds, TimeUnit.SECONDS);       
    }

    /**
     * refresh cache with Primary and Cluster Coordinator Node info
     */
    private void refreshCache() {
        final String primaryNode = findLeader(PRIMARY_NODE);
        final String coordinateNode = findLeader(CLUSTER_COORDINATOR);
        synchronized(cache) {
            cache.clear();
            if(!StringUtils.isBlank(primaryNode)) {
                logger.debug(String.format("caching primary Node : %s", primaryNode));
                cache.put(PRIMARY_NODE, primaryNode);
            }    
            if(!StringUtils.isBlank(coordinateNode)) {
                logger.debug(String.format("caching cluster coordinate Node : %s", coordinateNode));
                cache.put(CLUSTER_COORDINATOR, coordinateNode);
            }
        }   
    }
    /**
     * retreives the map of primary and coordinate node collected by the scheduler
     * @return map of primary and coordinate node collected
     */
    public Map<String, String> getCachedDataFromScheduler(){
        logger.debug("calling getCachedDataFromScheduler");
        if(this.cache.size() == 0) {
            refreshCache();
        }
        logger.debug("returning " + this.cache.size() + " from cache");
        return Collections.unmodifiableMap(this.cache);

    }
    /**
     * This will be called and shutdown the scheduler
     */
    public void stopScheduler(){
        try {
            scheduler.shutdownNow();
        } catch (final Exception e) {
            logger.warn("Error shutting down refresh scheduler: " + e.getMessage(), e);
        }
    } 

    private class SaslACLProvider implements ACLProvider{

        private final List<ACL> acls;

        private SaslACLProvider() {

            if(!StringUtils.isEmpty(authPrincipal)) {

                final String realm = authPrincipal.substring(authPrincipal.indexOf('@') + 1, authPrincipal.length());
                final String[] user = authPrincipal.substring(0, authPrincipal.indexOf('@')).split("/");
                final String host = user.length == 2 ? user[1] : null;
                final String instance = user[0];
                final StringBuilder principal = new StringBuilder(instance);

                if (!removeHostFromPrincipal.equalsIgnoreCase("true")) {
                    principal.append("/");
                    principal.append(host);
                }

                if (!removeRealmFromPrincipal.equalsIgnoreCase("true")) {
                    principal.append("@");
                    principal.append(realm);
                }

                this.acls = Lists.newArrayList(new ACL(ZooDefs.Perms.ALL, new Id(SASL_AUTH_SCHEME, principal.toString())));
                this.acls.addAll(ZooDefs.Ids.READ_ACL_UNSAFE);

            }else{
                throw new IllegalArgumentException("No Kerberos Principal configured for use with SASL Authentication Scheme");
            }
        }

        @Override
        public List<ACL> getDefaultAcl() {
            return acls;
        }

        @Override
        public List<ACL> getAclForPath(String s) {
            return acls;
        }
    }

    public String getZkConnectionString() {
        return zkConnectionString;
    }

    public void setZkConnectionString(String zkConnectionString) {
        this.zkConnectionString = zkConnectionString;
    }

    public String getRootPath() {
        return rootPath;
    }

    public void setRootPath(String rootPath) {
        this.rootPath = rootPath;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public String getAuthPrincipal() {
        return authPrincipal;
    }

    public void setAuthPrincipal(String authPrincipal) {
        this.authPrincipal = authPrincipal;
    }

    public String getRemoveHostFromPrincipal() {
        return removeHostFromPrincipal;
    }

    public void setRemoveHostFromPrincipal(String removeHostFromPrincipal) {
        this.removeHostFromPrincipal = removeHostFromPrincipal;
    }

    public String getRemoveRealmFromPrincipal() {
        return removeRealmFromPrincipal;
    }

    public void setRemoveRealmFromPrincipal(String removeRealmFromPrincipal) {
        this.removeRealmFromPrincipal = removeRealmFromPrincipal;
    }

    public static class Builder {
        private String zkConnectionString;
        private String rootPath;
        private String authType;
        private String authPrincipal;
        private String removeHostFromPrincipal;
        private String removeRealmFromPrincipal;


        public Builder(){
        }
    

        public Builder setZkConnectionString(String zkConnectionString) {
            this.zkConnectionString = zkConnectionString;
            rootPath = "/nifi";
            authType = "default";
            authPrincipal= "";
            removeHostFromPrincipal= "";
            removeRealmFromPrincipal = "";
            return this;
        }

        public Builder setRootPath(String rootPath) {
            this.rootPath = rootPath;
            return this;
        }

        public Builder setAuthType(String authType) {
            this.authType = authType;
            return this;
        }
    
        public Builder setAuthPrincipal(String authPrincipal) {
            this.authPrincipal = authPrincipal;
            return this;
        }

        public Builder setRemoveHostFromPrincipal(String removeHostFromPrincipal) {
            this.removeHostFromPrincipal = removeHostFromPrincipal;
            return this;
        }

    
        public Builder setRemoveRealmFromPrincipal(String removeRealmFromPrincipal) {
            this.removeRealmFromPrincipal = removeRealmFromPrincipal;
            return this;
        }
        
        public NiFiLeaderFinder build() {
            NiFiLeaderFinder finder = new NiFiLeaderFinder(zkConnectionString, rootPath);
            finder.setAuthType(authType);
            finder.setAuthPrincipal(authPrincipal);
            finder.setRemoveHostFromPrincipal(removeHostFromPrincipal);
            finder.setRemoveRealmFromPrincipal(removeRealmFromPrincipal);
            return finder;

        }
    }


    
}
