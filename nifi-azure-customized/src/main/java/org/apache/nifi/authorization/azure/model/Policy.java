package org.apache.nifi.authorization.azure.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.apache.nifi.authorization.AccessPolicy;
import org.apache.nifi.authorization.RequestAction;
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

import dev.morphia.annotations.Entity;
import dev.morphia.annotations.Id;
import dev.morphia.annotations.Property;

@Entity(Policy.ENTITY_COLLECTION_NAME)
public class Policy {
    @Id
    private String identifier;
    @Property
    private String resource;
    @Property
    private String action;
    @Property("group_ids")
    private List<String> groupIds = new ArrayList<>();
    @Property("user_ids")
    private List<String> userIds = new ArrayList<>();

    public static final String ENTITY_COLLECTION_NAME = "policies";

    public Policy(){
    }

    public Policy(final Builder builder){
        this.identifier = builder.identifier;
        this.resource = builder.resource;
        this.action = builder.action;
        this.userIds = new ArrayList<>(builder.users);
        this.groupIds = new ArrayList<>(builder.groups);

        if (this.identifier == null || this.identifier.trim().isEmpty()) {
            throw new IllegalArgumentException("Identifier can not be null or empty");
        }

        if (this.resource == null) {
            throw new IllegalArgumentException("Resource can not be null");
        }

        if (this.action == null) {
            throw new IllegalArgumentException("Action can not be null");
        }
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }

    public List<String> groupIds(){
        return groupIds;
    }
    public List<String> userIds(){
        return userIds;
    }

    public AccessPolicy convertToNifiAccessPolicy(){
        AccessPolicy.Builder builder = new AccessPolicy.Builder();
        builder.identifier(this.identifier)
        .resource(this.resource);
        if(RequestAction.READ.toString().equals(action)){
            builder.action(RequestAction.READ);
        } else {
            builder.action(RequestAction.WRITE);
        }
        builder.addGroups(new HashSet<>(groupIds));
        builder.addUsers(new HashSet<>(userIds));

        return builder.build();
    }

    public static class Builder {

        private String identifier;
        private String resource;
        private String action; // read or write
        private List<String> users;
        private List<String> groups;

        public Builder() {
            users = new ArrayList<>();
            groups = new ArrayList<>();
        }

        public Builder(final AccessPolicy policy) {
            this.identifier = policy.getIdentifier();
            this.resource = policy.getResource();
            this.action = policy.getAction().toString();
            this.users = new ArrayList<>(policy.getUsers());
            this.groups = new ArrayList<>(policy.getGroups());
        }

        public String getIdentifier() {
            return identifier;
        }

        public void setIdentifier(String identifier) {
            this.identifier = identifier;
        }

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            if (!RequestAction.READ.toString().equals(action) && !RequestAction.WRITE.toString().equals(action)) {
                throw new IllegalArgumentException(
                    "Action must be one of [" + RequestAction.READ.toString() + ", "
                    + RequestAction.WRITE.toString() + "]");
            }
            this.action = action;
        }

        public void addGroup(String group_id) {
            if(!groups.contains(group_id)){
                groups.add(group_id);
            }

        }

        public void addUser(String user_id){
            if(!users.contains(user_id)){
                users.add(user_id);
            }
        }

        public Policy build(){
            return new Policy(this);

        }


    }


}