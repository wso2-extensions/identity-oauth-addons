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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.impl;

import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.JWTAuthenticationConfigurationDAO;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceServerException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.util.Util;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.Constants.JWT_CONFIGURATION_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.Constants.JWT_CONFIGURATION_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.ErrorMessage.ERROR_CODE_PK_JWT_CONFIG_RETRIEVE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.util.ErrorUtils.handleServerException;

/**
 * DAO layer for JWT Authenticator Configurations.
 */
public class JWTAuthenticationConfigurationDAOImpl implements JWTAuthenticationConfigurationDAO {

    /**
     * {@inheritDoc}
     */
    @Override
    public int getPriority() {
        return 10;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JWTClientAuthenticatorConfig getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain
    (String tenantDomain) throws JWTClientAuthenticatorServiceServerException {

        try {

            Resource resource = getResource(JWT_CONFIGURATION_RESOURCE_TYPE_NAME, JWT_CONFIGURATION_RESOURCE_NAME);
            JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig;
            if (resource == null) {
                JWTClientAuthenticatorConfig = Util.getServerConfiguration();
            } else {
                JWTClientAuthenticatorConfig = Util.parseResource(resource);
            }
            return JWTClientAuthenticatorConfig;
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_PK_JWT_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain
    (JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig, String tenantDomain)
            throws JWTClientAuthenticatorServiceServerException {

        try {
            ResourceAdd resourceAdd = Util.parseConfig(jwtClientAuthenticatorConfig);
            getConfigurationManager().replaceResource(JWT_CONFIGURATION_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_PK_JWT_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    /**
     * Retrieve the ConfigurationManager instance from the JWTServiceDataHolder.
     *
     * @return ConfigurationManager The ConfigurationManager instance.
     */
    private ConfigurationManager getConfigurationManager() {

        return JWTServiceDataHolder.getInstance().getConfigurationManager();
    }

    /**
     * Configuration Management API returns a ConfigurationManagementException with the error code CONFIGM_00017 when
     * resource is not found. This method wraps the original method and returns null if the resource is not found.
     *
     * @param resourceTypeName Resource type name.
     * @param resourceName     Resource name.
     * @return Retrieved resource from the configuration store. Returns {@code null} if the resource is not found.
     * @throws ConfigurationManagementException
     */
    private Resource getResource(String resourceTypeName, String resourceName) throws ConfigurationManagementException {

        try {
            return getConfigurationManager().getResource(resourceTypeName, resourceName);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {
                return null;
            } else {
                throw e;
            }
        }
    }
}
