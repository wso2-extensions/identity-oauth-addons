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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant;

/**
 * Constants listed here for the Core Component.
 */
public class Constants {

    public static final String ENABLE_TOKEN_REUSE = "EnableTokenReuse";

    /**
     * Name of the {@code  JWTClientAuthenticatorConfig} resource type in the Configuration Management API.
     */
    public static final String JWT_CONFIGURATION_RESOURCE_TYPE_NAME = "PK_JWT_CONFIGURATION";

    /**
     * Name of the {@code JWTClientAuthenticatorConfig} resource (per tenant) in the Configuration Management API.
     */
    public static final String JWT_CONFIGURATION_RESOURCE_NAME = "TENANT_PK_JWT_CONFIGURATION";

    /**
     * Description of the {@code JWTClientAuthenticatorConfig} resource type in the Configuration Management API.
     */
    public static final String JWT_CONFIGURATION_RESOURCE_TYPE_DESCRIPTION =
            "A resource type to keep the tenant private key jwt configuration.";
}
