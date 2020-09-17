package org.apache.nifi.authorization.azure;

import static org.junit.Assert.assertNotNull;

import java.util.Properties;

import org.apache.curator.framework.CuratorFramework;
import org.apache.nifi.util.NiFiProperties;
import org.junit.Test;

/**
 * This Integration test only works inside NiFi Cluster
 */
public class NiFiLeaderFinderIT extends BaseIT {

    @Test
    public void testFactoryNifiLeaderFinder() {
        final Properties props = new Properties();
        
        props.setProperty(NiFiProperties.ZOOKEEPER_CONNECT_STRING, "10.251.0.7:2181,10.251.0.4:2181,10.251.0.5:2181");
        props.setProperty("nifi.zookeeper.root.node", "/nifi");
        props.setProperty(NiFiProperties.ZOOKEEPER_AUTH_TYPE, "");
        props.setProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_HOST_FROM_PRINCIPAL, "");
        props.setProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_REALM_FROM_PRINCIPAL, "");
        
        NiFiProperties properties = getNiFiProperties(props);

        NiFiLeaderFinder finder = NiFiLeaderFinder.create(properties);
        assertNotNull(finder);// exepects no IllegalStateException and reach upto this line
    }
    @Test
    public void testNifiLeaderFinderWithDefaultACLProperties() {
        final Properties props = new Properties();
        
        props.setProperty(NiFiProperties.ZOOKEEPER_CONNECT_STRING, "10.251.0.7:2181,10.251.0.4:2181,10.251.0.5:2181");
        props.setProperty("nifi.zookeeper.root.node", "/nifi");
        props.setProperty(NiFiProperties.ZOOKEEPER_AUTH_TYPE, "");
        props.setProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_HOST_FROM_PRINCIPAL, "");
        props.setProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_REALM_FROM_PRINCIPAL, "");
        
        NiFiProperties properties = getNiFiProperties(props);
        NiFiLeaderFinder finder = NiFiLeaderFinder.create(properties);
        final String primaryNode = finder.findLeader(NiFiLeaderFinder.PRIMARY_NODE);
        final String coordinateNode = finder.findLeader(NiFiLeaderFinder.CLUSTER_COORDINATOR);
        assertNotNull(primaryNode);
        assertNotNull(coordinateNode);
    }
    @Test
    public void testSaslACLProvider() {
        final Properties props = new Properties();
        
        props.setProperty(NiFiProperties.ZOOKEEPER_CONNECT_STRING, "10.251.0.7:2181,10.251.0.4:2181,10.251.0.5:2181");
        props.setProperty(NiFiProperties.ZOOKEEPER_ROOT_NODE, "/nifi");
        props.setProperty(NiFiProperties.KERBEROS_SERVICE_PRINCIPAL, "instance/host@domain");
        props.setProperty(NiFiProperties.ZOOKEEPER_AUTH_TYPE, NiFiLeaderFinder.SASL_AUTH_SCHEME);
        props.setProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_HOST_FROM_PRINCIPAL,"false");
        props.setProperty(NiFiProperties.ZOOKEEPER_KERBEROS_REMOVE_REALM_FROM_PRINCIPAL, "false");
        
        NiFiProperties properties = getNiFiProperties(props);
        NiFiLeaderFinder finder = NiFiLeaderFinder.create(properties);
        CuratorFramework cf =  finder.createClient();
        assertNotNull(cf);// exepects no IllegalStateException and reach upto this line
    }

}
