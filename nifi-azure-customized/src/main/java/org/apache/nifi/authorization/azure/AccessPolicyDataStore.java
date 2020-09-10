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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoIterable;

import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.azure.model.Policy;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dev.morphia.Datastore;
import dev.morphia.Morphia;
import dev.morphia.query.Query;

/**
 * AccessPolicyDataStore stores and retrieves AccessPolicy(s) and supports a limited query from Mongo DB.
 * Azure customer may setup a Azure Cosmos DB with Mongo API, while Non-Azure customer may setup its own Mongo DB instance instead.
 * It requres a database with a collection called 'policies' in advance and will throws AuthorizationAccessException otherwise.
 */
public class AccessPolicyDataStore {
    final MongoClient mongoClient;
    final Morphia morphia;
    final Datastore datastore;
    private static final Logger logger = LoggerFactory.getLogger(AccessPolicyDataStore.class);

    public AccessPolicyDataStore(final MongoClientURI mongoClientURI, final String databaseName){
        mongoClient = new MongoClient(mongoClientURI);
        checkDatabaseCollectionExists(databaseName);
        morphia = new Morphia();
        final String packageName = Policy.class.getPackageName();
        morphia.mapPackage(packageName);
        datastore = morphia.createDatastore(mongoClient, databaseName);
        datastore.ensureIndexes();

    }

    private void checkDatabaseCollectionExists(final String databaseName) throws AuthorizationAccessException{
        final MongoDatabase mongoDB = mongoClient.getDatabase(databaseName);

        MongoIterable<String> collections =  mongoDB.listCollectionNames();
        boolean collection_exists = false;
        for(String collection: collections){
            if(collection.equals(Policy.ENTITY_COLLECTION_NAME)){
                collection_exists = true;
            }
        }
        if(!collection_exists){
            // we don't create an database and collection 'policy' at run time,
            // since this object could be run in multiple nodes in a cluster mode
            final String error = String.format(
                "'policies' collection under %s does not exist. Create database and collection first."
                ,databaseName);
            throw new AuthorizerCreationException(error);
        }
    }

    public Set<AccessPolicy> getAccessPolicies() throws AuthorizationAccessException {
        final Set<AccessPolicy> policies = new HashSet<>();
        // retrieve raw json data from database, unmarshall, and return
        logger.debug("db call: getAccessPolicies()");
        final List<Policy> policyData = datastore.createQuery(Policy.class).find().toList();

        for (final Policy policy : policyData) {
            final AccessPolicy nifiAccessPolicy = policy.convertToNifiAccessPolicy();
            policies.add(nifiAccessPolicy);
        }

        return policies;

    }

    public AccessPolicy getAccessPolicy(final String identifier) throws AuthorizationAccessException {
        logger.debug("db call: getAccessPolicy(identifier)");
        final List<Policy> policyQuery = datastore.createQuery(Policy.class).field("identifier").equal(identifier)
                .find().toList();
        if (policyQuery.size() == 1) {
            final Policy top = policyQuery.get(0);
            return top.convertToNifiAccessPolicy();
        } else {
            return null;
        }

    }

    public AccessPolicy getAccessPolicy(final String resourceName, final String action)
            throws AuthorizationAccessException {
        logger.debug("db call: getAccessPolicy(resourceName, action)");
        final List<Policy> policyQuery = datastore.createQuery(Policy.class).field("resource").equal(resourceName)
                .field("action").equal(action).find().toList();
        if (policyQuery.size() == 1) {
            final Policy top = policyQuery.get(0);
            return top.convertToNifiAccessPolicy();
        } else {
            return null;
        }
    }

    public AccessPolicy addInitialAccessPolicyConfig(final AccessPolicy accessPolicy) throws AuthorizationAccessException {
        // to avoid the initial access policy config multiple time, check if the polcy defined already
        if(getAccessPolicy(accessPolicy.getResource(), accessPolicy.getAction().toString()) == null){
            return addAccessPolicy(accessPolicy);
        } else{
            return null;
        }

    }

    public AccessPolicy addAccessPolicy(final AccessPolicy accessPolicy) throws AuthorizationAccessException {
        final Policy data = new Policy.Builder(accessPolicy).build();
        datastore.save(data);
        return getAccessPolicy(accessPolicy.getIdentifier());
    }

    public AccessPolicy updateAccessPolicy(final AccessPolicy accessPolicy) throws AuthorizationAccessException {
        final List<Policy> policyQuery = datastore.createQuery(Policy.class)
                .field("identifier").equal(accessPolicy.getIdentifier())
                .find().toList();
        if (policyQuery.size() == 1) {
            final Policy top = policyQuery.get(0);
            if(top.getResource().equals(accessPolicy.getResource()) && top.getAction().equals(accessPolicy.getAction().toString()) ){
                final Policy data = new Policy.Builder(accessPolicy).build();
                datastore.save(data);
                return getAccessPolicy(accessPolicy.getIdentifier());
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    public AccessPolicy deleteAccessPolicy(final AccessPolicy accessPolicy) throws AuthorizationAccessException {
        final Query<Policy> query = datastore.createQuery(Policy.class)
                                .field("identifier")
                                .equal(accessPolicy.getIdentifier());

        datastore.delete(query);
        // 'testDeleteAccessPolicy' test case from FileAccessPolicy expects to return a non-null AccessPolicy, thus
        // this method just returns the input accessPolicy.
        return accessPolicy;
    }

}