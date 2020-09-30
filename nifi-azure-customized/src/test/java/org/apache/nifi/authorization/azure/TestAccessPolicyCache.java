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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.HashSet;
import java.util.Set;

import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.RequestAction;
import org.junit.Test;

public class TestAccessPolicyCache {
    @Test
    public void TestCacheReset() {

        Set<AccessPolicy> policies = new HashSet<>();

        final AccessPolicy policy1 = new AccessPolicy.Builder()
                .identifier("policy-1")
                .resource("resource-1")
                .addUser("user-1")
                .addGroup("group-1")
                .action(RequestAction.READ)
                .build();

        final AccessPolicy policy2 = new AccessPolicy.Builder()
                .identifier("policy-2")
                .resource("resource-2")
                .addUser("user-1")
                .addGroup("group-1")
                .action(RequestAction.READ)
                .build();

        policies.add(policy1);
        policies.add(policy2);
        long cacheTimeoutInSeconds = 5;
        AccessPolicyCache cache = new AccessPolicyCache(cacheTimeoutInSeconds);
        cache.resetCache(policies);
        assertNotNull(cache.getAccessPolicyFromCache(policy1.getIdentifier()));
        try {
            Thread.sleep((cacheTimeoutInSeconds + 1) * 1000);
        } catch(Exception e){

        }
        assertNull(cache.getAccessPolicyFromCache(policy1.getIdentifier()));

        cache.resetCache(policies);
        assertNotNull(cache.getAccessPolicyFromCache(policy1.getIdentifier()));

    }

    
}
