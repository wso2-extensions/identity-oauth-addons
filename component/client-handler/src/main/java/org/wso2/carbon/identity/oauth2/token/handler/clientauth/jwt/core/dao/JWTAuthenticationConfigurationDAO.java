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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao;

import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceServerException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;

/**
 * Perform CRUD operations for {@link JWTClientAuthenticatorConfig}.
 */
public interface JWTAuthenticationConfigurationDAO {

    /**
     * Get priority value for the {@link JWTAuthenticationConfigurationDAO}.
     *
     * @return Priority value for the DAO.
     */
    int getPriority();

    /**
     * Get the JWT Authenticator configuration of a tenant.
     *
     * @param tenantDomain The tenant domain.
     * @return JWTClientAuthenticatorConfig The configuration model.
     * @throws JWTClientAuthenticatorServiceServerException JWTClientAuthenticatorServiceServerException
     */
    JWTClientAuthenticatorConfig getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(String tenantDomain)
            throws JWTClientAuthenticatorServiceServerException;

    /**
     * Set the JWT Authenticator configuration of a tenant.
     *
     * @param JWTClientAuthenticatorConfig The new JWT Authenticator configuration to be set.
     * @param tenantDomain                 The tenant domain.
     * @throws JWTClientAuthenticatorServiceServerException JWTClientAuthenticatorServiceServerException
     */
    void setPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig, String tenantDomain)
            throws JWTClientAuthenticatorServiceServerException;
}
