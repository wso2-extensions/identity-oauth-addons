/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model;

/**
 * JWT Client Authenticator Configuration Model class for DAOs.
 */
public class JWTClientAuthenticatorConfig {

    /**
     * If {@code true} JTI for JWT can be reused only if previous JWT expires,
     * else JTI is unique even after the expiration.
     */
    private boolean enableTokenReuse;

    public boolean isEnableTokenReuse() {

        return enableTokenReuse;
    }

    public void setEnableTokenReuse(boolean enableTokenReuse) {

        this.enableTokenReuse = enableTokenReuse;
    }
}
