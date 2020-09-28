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

public class AccessPolicyCache {
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
        final Map<String, Instant> newPolicyIdToTimestamp = new HashMap<>();
        final Map<String, AccessPolicy> newPoliciesById = new HashMap<>();
        final Map<String, String> newResourceIdAndActionToPolicyId = new HashMap<>();

        Instant timestamp = Instant.now();
        for(AccessPolicy policy: policies) {
            newPolicyIdToTimestamp.put(policy.getIdentifier(), timestamp);
            newPoliciesById.put(policy.getIdentifier(), policy);
            newResourceIdAndActionToPolicyId.put(
                getResourceActionKey(policy.getResource(), policy.getAction()),
                policy.getIdentifier());
        }


        this.policiesById.clear();
        this.resourceNameAndActionToPolicyId.clear();
        this.policyIdToTimestamp.clear();
        this.policyIdToTimestamp = newPolicyIdToTimestamp;
        this.policiesById = newPoliciesById;
        this.resourceNameAndActionToPolicyId = newResourceIdAndActionToPolicyId;
        this.lastTimeStamp = timestamp;
    }

    public void cachePolicy(AccessPolicy policy){
        if (policy !=null) {
            Instant timeStamp = Instant.now();
            final AccessPolicy foundPolicy = this.policiesById.get(policy.getIdentifier());
            if(foundPolicy != null){
                // clean up foundPolicy
                this.remove(policy);
            }
            this.policiesById.put(policy.getIdentifier(), policy);
            this.policyIdToTimestamp.put(policy.getIdentifier(), timeStamp);
            this.resourceNameAndActionToPolicyId.put(
                getResourceActionKey(policy.getResource(), policy.getAction()),
                policy.getIdentifier());
            // update last time stamp at the cache level
            this.lastTimeStamp = timeStamp;

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
        final Instant timeStamp = Instant.now();
        final AccessPolicy foundPolicy = this.policiesById.get(policyId);
        if(foundPolicy != null){
            // check if cached policy is expired
            final Instant lastTimestamp = policyIdToTimestamp.get(policyId);
            if(lastTimestamp != null) {
                if(Duration.between(lastTimestamp, timeStamp).getSeconds() < cacheDurationBySeconds) {
                    return foundPolicy;
                } else {
                    this.policiesById.remove(policyId);
                    this.resourceNameAndActionToPolicyId.remove(
                        getResourceActionKey(foundPolicy.getResource(), foundPolicy.getAction()));
                }
            } else {
                this.policyIdToTimestamp.remove(policyId);
                this.policiesById.remove(policyId);
                this.resourceNameAndActionToPolicyId.remove(
                    getResourceActionKey(foundPolicy.getResource(), foundPolicy.getAction()));
            }
        }
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