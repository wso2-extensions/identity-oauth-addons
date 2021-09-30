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
public class DPoPConstants {

    public static final String OAUTH_CONFIG_ELEMENT = "OAuth";
    public static final String DPOP_CONFIG_ELEMENT = "DPoPConfig";
    public static final String DPOP_ENABLED = "Enable";
    public static final String HEADER_VALIDITY = "OAuth.DPoPConfig.HeaderValidity";
    public static final int DEFAULT_HEADER_VALIDITY = 60000;
    public static final String DPOP_ISSUED_AT = "iat";
    public static final String DPOP_HTTP_URI = "htu";
    public static final String DPOP_HTTP_METHOD = "htm";
    public static final String DPOP_JWT_TYPE = "dpop+jwt";
    public static final String DPOP_TOKEN_TYPE = "DPoP";
    public static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";
    public static final String INVALID_DPOP_ERROR = "Invalid DPoP Proof";
    public static final String ECDSA_ENCRYPTION = "EC";
    public static final String RSA_ENCRYPTION = "RSA";

    public static final String OAUTH_HEADER = "Bearer";
    public static final String JTI = "jti";
    public static final String OAUTH_DPOP_HEADER = "DPoP";
    public static final String CNF = "cnf";
    public static final String TOKEN_TYPE = "token_type";
    public static final String JWK_THUMBPRINT = "jkt";
    public static final String AUTHORIZATION_HEADER = "authorization";

    /**
     * This class defines SQLQueries.
     */
    public static class SQLQueries {

        public static final String RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN =
                "SELECT BINDING.TOKEN_BINDING_TYPE,BINDING.TOKEN_BINDING_VALUE FROM IDN_OAUTH2_ACCESS_TOKEN TOKEN " +
                        "LEFT JOIN IDN_OAUTH2_TOKEN_BINDING BINDING ON " +
                        "TOKEN.TOKEN_BINDING_REF=BINDING.TOKEN_BINDING_REF WHERE TOKEN.REFRESH_TOKEN = ?";
    }
}
