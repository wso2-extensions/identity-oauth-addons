/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao;

/**
 * A model class which is use to persist the JWT token in database as JWTEntry objects.
 */
public class JWTEntry {

    private long exp;
    private long createdTime;

    private int tenantId;

    public JWTEntry(long exp, long createdTime) {

        this.exp = exp;
        this.createdTime = createdTime;
    }

    public JWTEntry(long exp, long createdTime, int tenantId) {

        this.exp = exp;
        this.createdTime = createdTime;
        this.tenantId = tenantId;
    }

    public long getExp() {

        return exp;
    }

    public long getCreatedTime() {

        return createdTime;
    }

    public int getTenantId() {

        return tenantId;
    }
}
