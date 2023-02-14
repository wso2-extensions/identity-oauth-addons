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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core;

import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;

/**
 * Service for managing the JWT Authenticator configurations of a tenant.
 */
public interface JWTClientAuthenticatorMgtService {

    /**
     * Get the JWT Authenticator configurations of a tenant.
     *
     * @param tenantDomain The tenant domain.
     * @return JWTClientAuthenticatorConfig Returns an instance of {@code JWTClientAuthenticatorConfig} belonging to the tenant.
     * @throws JWTClientAuthenticatorServiceException
     */
    JWTClientAuthenticatorConfig getPrivateKeyJWTClientAuthenticatorConfiguration(String tenantDomain)
            throws JWTClientAuthenticatorServiceException;

    /**
     * Set the JWT Authenticator configurations of a tenant.
     *
     * @param jwtClientAuthenticatorConfig The {@code JWTClientAuthenticatorConfig} object to be set.
     * @param tenantDomain                 The tenant domain.
     * @throws JWTClientAuthenticatorServiceException
     */
    void setPrivateKeyJWTClientAuthenticatorConfiguration(
            JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig, String tenantDomain)
            throws JWTClientAuthenticatorServiceException;
}
