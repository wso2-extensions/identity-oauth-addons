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

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.ErrorMessage;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceClientException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;

import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.util.ErrorUtils.handleClientException;

/**
 * Implementation of Service for managing the JWT Authenticator configurations of a tenant.
 */
public class JWTClientAuthenticatorMgtServiceImpl implements JWTClientAuthenticatorMgtService {

    /**
     * {@inheritDoc}
     */
    @Override
    public JWTClientAuthenticatorConfig getPrivateKeyJWTClientAuthenticatorConfiguration
    (String tenantDomain) throws JWTClientAuthenticatorServiceException {

        validateTenantDomain(tenantDomain);

        JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig
                = JWTServiceDataHolder.getInstance()
                .getPrivateKeyJWTAuthenticationConfigurationDAO()
                .getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(tenantDomain);
        return JWTClientAuthenticatorConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPrivateKeyJWTClientAuthenticatorConfiguration
    (JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig, String tenantDomain)
            throws JWTClientAuthenticatorServiceException {

        validateTenantDomain(tenantDomain);
        JWTServiceDataHolder.getInstance().getPrivateKeyJWTAuthenticationConfigurationDAO()
                .setPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain
                        (JWTClientAuthenticatorConfig, tenantDomain);


    }

    /**
     * Validate the tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @throws JWTClientAuthenticatorServiceClientException
     */
    private void validateTenantDomain(String tenantDomain)
            throws JWTClientAuthenticatorServiceClientException {

        try {
            IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            throw handleClientException(ErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, tenantDomain);
        }
    }
}
