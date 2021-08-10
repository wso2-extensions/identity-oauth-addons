/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
 * under the License
 */

package org.wso2.carbon.identity.dpop.constant;

/**
 * This class defines constants for Oauth2 DPoP validation.
 */
public class Constants {

    public static final String DPOP_CONFIG_ELEMENT = "OAuth.DPoPConfig";
    public static final String HEADER_VALIDITY = "HeaderValidity";
    public static final int DEFAULT_HEADER_VALIDITY = 60000;
    public static final String DPOP_ISSUED_AT = "iat";
    public static final String DPOP_HTTP_URI = "htu";
    public static final String DPOP_HTTP_METHOD = "htm";
    public static final String DPOP_JWT_TYPE = "dpop+jwt";
    public static final String DPOP_TOKEN_TYPE = "DPoP";
    public static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";

    public static final String ECDSA_ENCRYPTION = "EC";
    public static final String RSA_ENCRYPTION = "RSA";

    public static final String OAUTH_HEADER = "Bearer";
    public static final String OAUTH_DPOP_HEADER = "DPoP";
    public static final String CONSUMER_KEY = "consumer-key";
    public static final String SERVICE_PROVIDER = "serviceProvider";
    public static final String SERVICE_PROVIDER_TENANT_DOMAIN = "serviceProviderTenantDomain";
    public static final String SCIM_ME_ENDPOINT_URI = "scim2/me";
}