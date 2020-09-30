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

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.RequestAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessPolicyCache {
    private static final Logger logger = LoggerFactory.getLogger(AccessPolicyCache.class);
    private Map<String, Instant> policyIdToTimestamp;
    private Map<String, AccessPolicy> policiesById;
    private Map<String, String> resourceNameAndActionToPolicyId; // map (resourceName + action) => policyId
    private long cacheDurationBySeconds;
    private Instant lastTimeStamp;

    public AccessPolicyCache(long cacheDurationBySeconds) {
        this.cacheDurationBySeconds = cacheDurationBySeconds;
        policyIdToTimestamp = new HashMap<>();
        policiesById = new HashMap<>();
        resourceNameAndActionToPolicyId = new HashMap<>();
        lastTimeStamp = null;
    }

    static String getResourceActionKey(String resourceName, RequestAction action){
        return String.format("%s_%s", resourceName, action.toString());
    }

    public boolean existDefinedPolicyFor(String policyId) {
        return policiesById.keySet().contains(policyId);
    }

    public boolean existDefinedPolicyFor(String resourceName, RequestAction action) {
        final String key = getResourceActionKey(resourceName, action);
        return resourceNameAndActionToPolicyId.keySet().contains(key);
    }

    public void resetCache(Set<AccessPolicy> policies) {
        if(policies ==null || policies.size() == 0) {
            return; // dont do anything if input is empty
        }
        Map<String, Instant> newPolicyIdToTimestamp = new HashMap<>();
        Map<String, AccessPolicy> newPoliciesById = new HashMap<>();
        Map<String, String> newResourceIdAndActionToPolicyId = new HashMap<>();

        Instant now = Instant.now();
        for(AccessPolicy policy: policies) {
            newPolicyIdToTimestamp.put(policy.getIdentifier(), now);
            newPoliciesById.put(policy.getIdentifier(), policy);
            newResourceIdAndActionToPolicyId.put(
                getResourceActionKey(policy.getResource(), policy.getAction()),
                policy.getIdentifier());
        }
        this.policyIdToTimestamp = newPolicyIdToTimestamp;
        this.policiesById = newPoliciesById;
        this.resourceNameAndActionToPolicyId = newResourceIdAndActionToPolicyId;
        this.lastTimeStamp = now;
        logger.debug("Policy cache reset with " + policyIdToTimestamp.size());
    }

    public void cachePolicy(AccessPolicy policy){
        if (policy !=null) {
            Instant now = Instant.now();
            final AccessPolicy foundPolicy = this.policiesById.get(policy.getIdentifier());
            if(foundPolicy != null){
                // clean up foundPolicy
                this.remove(policy);
            }
            this.policiesById.put(policy.getIdentifier(), policy);
            this.policyIdToTimestamp.put(policy.getIdentifier(), now);
            this.resourceNameAndActionToPolicyId.put(
                getResourceActionKey(policy.getResource(), policy.getAction()),
                policy.getIdentifier());
            // update last time stamp at the cache level
            this.lastTimeStamp = now;

        }

    }
    public void remove(AccessPolicy policy) {
        if (policy !=null) {
            final AccessPolicy foundPolicy = this.policiesById.get(policy.getIdentifier());
            if(foundPolicy != null){
                // clean up foundPolicy
                this.policyIdToTimestamp.remove(policy.getIdentifier());
                this.policiesById.remove(policy.getIdentifier());
                this.resourceNameAndActionToPolicyId.remove(
                    getResourceActionKey(policy.getResource(), policy.getAction()));
            }
        }
    }

    public AccessPolicy getAccessPolicyFromCache(String policyId) {
        if(policyId == null)
            return null;
        final Instant now = Instant.now();
        final AccessPolicy foundPolicy = this.policiesById.get(policyId);
        if(foundPolicy != null){
            // check if cached policy is expired
            final Instant lastTimestamp = policyIdToTimestamp.get(policyId);
            if(lastTimestamp != null) {
                if(Duration.between(lastTimestamp, now).getSeconds() < cacheDurationBySeconds) {
                    return foundPolicy;
                }
                logger.debug("leave the invalidated cached policy behind so that it still supports existDefinedPolicyFor method");
                // leave the invalidated cached policy behind so that it still supports existDefinedPolicyFor method.
            }
        }
        // null returns means either it is not existings or expired policy
        return null;
    }

    public AccessPolicy getAccessPolicyFromCache(String resourceId, RequestAction action){
        if(resourceId == null || action == null)
            return null;
        final String foundPolicyId =
            this.resourceNameAndActionToPolicyId.get(
                getResourceActionKey(resourceId, action));

        if(foundPolicyId != null) {
            return getAccessPolicyFromCache(foundPolicyId);
        }
        return null;
    }

    public Set<AccessPolicy> getAccessPoliciesFromCache(){
        if(lastTimeStamp != null &&
            Duration.between(lastTimeStamp, Instant.now()).getSeconds() < cacheDurationBySeconds) {
            // return cached set of access policies
            return Collections.unmodifiableSet(new HashSet<>(policiesById.values()));
        }
        return null;
    }

}