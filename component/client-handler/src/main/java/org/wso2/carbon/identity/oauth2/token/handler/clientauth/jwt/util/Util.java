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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util;

import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.SQLQueries;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.isTableColumnExists;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.GET_JWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.GET_JWT_ID;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.GET_JWT_DETAILS;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.INSERT_JWD_ID;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_H2;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_MSSQL_DB2;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_MYSQL;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_ORACLE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_POSTGRESQL;


/**
 * Util method for jwt token handler component.
 */
public class Util {

    private static boolean isTenantIdColumnIsAvailableInIdnOidcAuthTable = false;
    private static Map<String, String> queries = new HashMap<>();

    public static boolean isTenantIdColumnAvailableInIdnOidcAuth() {

        return isTenantIdColumnIsAvailableInIdnOidcAuthTable;
    }

    public static String getDBQuery(String key) {

        return queries.get(key);
    }

    /**
     * Checking whether the tenant id column is available in the IDN_OIDC_JTI table.
     */
    public static void checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable() {

        isTenantIdColumnIsAvailableInIdnOidcAuthTable = isTableColumnExists(SQLQueries.IDN_OIDC_JTI,
                SQLQueries.TENANT_ID);
        buildQueryMapping();
    }

    private static void buildQueryMapping() {

        if (isTenantIdColumnIsAvailableInIdnOidcAuthTable) {
            queries.put(GET_JWT_ID, SQLQueries.GET_TENANTED_JWT_ID);
            queries.put(GET_JWT, SQLQueries.GET_TENANTED_JWT);
            queries.put(GET_JWT_DETAILS, SQLQueries.GET_JWT_DETAIL);
            queries.put(INSERT_JWD_ID, SQLQueries.INSERT_TENANTED_JWD_ID);
            queries.put(UPSERT_MSSQL_DB2, SQLQueries.INSERT_OR_UPDATE_TENANTED_JWT_ID_MSSQL_OR_DB2);
            queries.put(UPSERT_MYSQL, SQLQueries.INSERT_OR_UPDATE_TENANTED_JWT_ID_MYSQL);
            queries.put(UPSERT_H2, SQLQueries.INSERT_OR_UPDATE_TENANTED_JWT_ID_H2);
            queries.put(UPSERT_POSTGRESQL, SQLQueries.INSERT_OR_UPDATE_TENANTED_JWT_ID_POSTGRESQL);
            queries.put(UPSERT_ORACLE, SQLQueries.INSERT_OR_UPDATE_TENANTED_JWT_ID_ORACLE);
        } else {
            queries.put(GET_JWT_ID, SQLQueries.GET_JWT_ID);
            queries.put(GET_JWT, SQLQueries.GET_JWT);
            queries.put(INSERT_JWD_ID, SQLQueries.INSERT_JWD_ID);
            queries.put(UPSERT_MSSQL_DB2, SQLQueries.INSERT_OR_UPDATE_JWT_ID_MSSQL_OR_DB2);
            queries.put(UPSERT_MYSQL, SQLQueries.INSERT_OR_UPDATE_JWT_ID_MYSQL);
            queries.put(UPSERT_H2, SQLQueries.INSERT_OR_UPDATE_JWT_ID_H2);
            queries.put(UPSERT_POSTGRESQL, SQLQueries.INSERT_OR_UPDATE_JWT_ID_POSTGRESQL);
            queries.put(UPSERT_ORACLE, SQLQueries.INSERT_OR_UPDATE_JWT_ID_ORACLE);
        }
    }
}
