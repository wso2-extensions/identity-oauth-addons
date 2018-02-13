/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt;

/**
 * Constants are listed here
 */
public class Constants {

    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String OAUTH_JWT_ASSERTION = "client_assertion";
    public static final String OAUTH_JWT_ASSERTION_TYPE = "client_assertion_type";
    public static final int DEFAULT_VALIDITY_PERIOD_IN_MINUTES = 300;
    public static final String DEFAULT_TOKEN_EP_ALIAS = "";
    public static final boolean DEFAULT_ENABLE_JTI_CACHE = true;
    public static final String UTC = "UTC";
    public static final String TOKEN_ENDPOINT_ALIAS = "TokenEndpointAlias";
    public static final String PREVENT_TOKEN_REUSE = "PreventTokenReuse";
    public static final String REJECT_BEFORE_IN_MINUTES = "RejectBeforeInMinutes";
    public static final String ISSUER = "Issuer";
    public static final String JWT_ID_CLAIM = "jti";
    public static final String EXPIRATION_TIME_CLAIM = "exp";
    public static final String AUDIENCE_CLAIM = "aud";
    public static final String SUBJECT_CLAIM = "sub";
    public static final String ISSUER_CLAIM = "iss";
    public static final String PRIVATE_KEY_JWT = "signedJWT";

    public static class SQLQueries {

        public static final String GET_JWT_ID = "SELECT 1 FROM IDN_OIDC_JTI WHERE JWT_ID =?";
        public static final String GET_JWT = "SELECT EXP_TIME,TIME_CREATED FROM IDN_OIDC_JTI WHERE JWT_ID =?";
        public static final String INSERT_JWD_ID = "INSERT INTO IDN_OIDC_JTI (JWT_ID, EXP_TIME, TIME_CREATED)" +
                "VALUES (?,?,?)";
    }
}
