/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils;

/**
 * Common Constants for MTLS.
 */
public class CommonConstants {

    public static final String JWKS_URI = "jwksURI";
    public static final String CERT_THUMBPRINT = "x5t";
    public static final String SEPARATOR = "#";
    public static final String TIMESTAMP_SCOPE_PREFIX = "TIME_";
    public static final String CERT_THUMBPRINT_SEPARATOR = ":";
    public static final String CONFIRMATION_CLAIM_ATTRIBUTE = "cnf";
    public static final String SHA256_DIGEST_ALGORITHM = "SHA256";
    public static final String AUTHENTICATOR_TYPE_PARAM = "authenticatorType";
    public static final String AUTHENTICATOR_TYPE_MTLS = "mtls";
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String MTLS_AUTH_HEADER = "MutualTLS.ClientCertificateHeader";
    public static final String X5T = "x5t";
    public static final String X5C = "x5c";
    public static final String X509 = "X.509";
    public static final String HTTP_CONNECTION_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPConnectionTimeout";
    public static final String HTTP_READ_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPReadTimeout";
    public static final String KEYS = "keys";
    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String AUTHENTICATOR_TYPE_PK_JWT = "pkJWT";
    public static final String ENABLE_TLS_CERT_TOKEN_BINDING = "OAuth.OpenIDConnect." +
            "EnableTLSCertificateBoundAccessTokensViaBindingType";

}
