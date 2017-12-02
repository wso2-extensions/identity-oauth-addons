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

public class Constants {

    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String OAUTH_JWT_ASSERTION = "client_assertion";
    public static final String OAUTH_JWT_ASSERTION_TYPE = "client_assertion_type";
    public static final int DEFAULT_VALIDITY_PERIOD = 300;
    public static final String VALIDITY_PERIOD = "RejectBeforePeriod";
    public static final String PREVENT_TOKEN_REUSE = "PreventTokenReuse";
    public static final String AUDIENCE = "Audience";
    public static final String ISSUER = "Issuer";
    public static final String SUBJECT_FIELD = "SubjectField";
    public static final String SIGNED_BY = "SignedBy";
    public static final String SP = "SP";
    public static final String USE_CACHE_FOR_JTI = "EnableCacheForJTI";
    public static final boolean DEFAULT_USE_CACHE_FOR_JTI_VALUE = true;
    public static final String PROPERTIES_FILE = "jwt.properties";
    public static final String CLIENT_ID = "client_id";
    public static final String UTC = "UTC";

    public static class SQLQueries

    {
        public static final String GET_JWT_ID = "SELECT 1 FROM IDN_JWT_PRIVATE_KEY WHERE JWT_ID =?;";
        public static final String GET_JWT = "SELECT EXP_TIME,TIME_CREATED FROM IDN_JWT_PRIVATE_KEY WHERE JWT_ID =?;";
        public static final String INSERT_JWD_ID = "INSERT INTO IDN_JWT_PRIVATE_KEY (JWT_ID,EXP_TIME," +
                "TIME_CREATED)VALUES (?,?,?)";
    }

}