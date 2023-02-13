/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.DEFAULT_TENANT_ID;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.GET_JWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.GET_JWT_DETAILS;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.INSERT_JWD_ID;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.SQLQueries.EXP_TIME;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.SQLQueries.TENANT_ID;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.SQLQueries.TIME_CREATED;

import static org.wso2.carbon.identity.core.util.JdbcUtils.isDB2DB;
import static org.wso2.carbon.identity.core.util.JdbcUtils.isH2DB;
import static org.wso2.carbon.identity.core.util.JdbcUtils.isMSSqlDB;
import static org.wso2.carbon.identity.core.util.JdbcUtils.isMariaDB;
import static org.wso2.carbon.identity.core.util.JdbcUtils.isMySQLDB;
import static org.wso2.carbon.identity.core.util.JdbcUtils.isOracleDB;
import static org.wso2.carbon.identity.core.util.JdbcUtils.isPostgreSQLDB;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_H2;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_MSSQL_DB2;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_MYSQL;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_ORACLE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.UPSERT_POSTGRESQL;

/**
 * JWT token persistence is managed by JWTStorageManager
 * It saved JWTEntry instances in IDN_OIDC_JTI table of Identity Database.
 */
public class JWTStorageManager {

    private static final Log log = LogFactory.getLog(JWTStorageManager.class);

    /**
     * To get a list of persisted JWTs for a given JTI.
     *
     * @param jti JTI.
     * @return List of JWTEntries.
     * @throws OAuthClientAuthnException OAuthClientAuthnException thrown with Invalid Request error code.
     */
    public List<JWTEntry> getJwtsFromDB(String jti, int tenantId) throws OAuthClientAuthnException {

        List<JWTEntry> JWTEntries = new ArrayList<>();

        Connection dbConnection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        try {
            if (Util.isTenantIdColumnIsAvailableInIdnOidcAuthTable()) {
                prepStmt = dbConnection.prepareStatement(Util.getDBQuery(GET_JWT_DETAILS));
                prepStmt.setString(1, jti);
                prepStmt.setInt(2, tenantId);
                prepStmt.setInt(3, DEFAULT_TENANT_ID);
                rs = prepStmt.executeQuery();
                while (rs.next()) {
                    int tenantID = rs.getInt(TENANT_ID);
                    long exp = rs.getTime(EXP_TIME,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))).getTime();
                    long created = rs.getTime(TIME_CREATED,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))).getTime();
                    JWTEntries.add(new JWTEntry(exp, created, tenantID));
                }
            } else {
                prepStmt = dbConnection.prepareStatement(Util.getDBQuery(GET_JWT));
                prepStmt.setString(1, jti);
                rs = prepStmt.executeQuery();
                while (rs.next()) {
                    long exp = rs.getTime(EXP_TIME,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))).getTime();
                    long created = rs.getTime(TIME_CREATED,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))).getTime();
                    JWTEntries.add(new JWTEntry(exp, created));
                }
            }

        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error when retrieving the JWT ID: " + jti + " tenant id: " + tenantId, e);
            }
            throw new OAuthClientAuthnException("Error occurred while validating the JTI: " + jti + " of the " +
                    "assertion.", OAuth2ErrorCodes.INVALID_REQUEST);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }
        return JWTEntries;
    }

    /**
     * To persist unique id for jti in the table.
     *
     * @param jti         JTI a unique id.
     * @param tenantId    Tenant id.
     * @param expTime     Expiration time.
     * @param timeCreated JTI inserted time.
     * @throws IdentityOAuth2Exception
     */
    public void persistJWTIdInDB(String jti, int tenantId, long expTime, long timeCreated) throws OAuthClientAuthnException {

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            if (JWTServiceDataHolder.getInstance().isPreventTokenReuse()) {
                preparedStatement = connection.prepareStatement(Util.getDBQuery(INSERT_JWD_ID));
                preparedStatement.setString(1, jti);
                if (Util.isTenantIdColumnIsAvailableInIdnOidcAuthTable()) {
                    preparedStatement.setInt(2, tenantId);
                    Timestamp timestamp = new Timestamp(timeCreated);
                    Timestamp expTimestamp = new Timestamp(expTime);
                    preparedStatement.setTimestamp(3, expTimestamp, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                    preparedStatement.setTimestamp(4, timestamp,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                } else {
                    Timestamp timestamp = new Timestamp(timeCreated);
                    Timestamp expTimestamp = new Timestamp(expTime);
                    preparedStatement.setTimestamp(2, expTimestamp, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                    preparedStatement.setTimestamp(3, timestamp,
                            Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                }
            } else {
                if (isH2DB()) {
                    preparedStatement = connection.prepareStatement(Util.getDBQuery(UPSERT_H2));
                } else if (isMySQLDB() || isMariaDB()) {
                    preparedStatement = connection.prepareStatement(Util.getDBQuery(UPSERT_MYSQL));
                } else if (isPostgreSQLDB()) {
                    preparedStatement = connection.prepareStatement(Util.getDBQuery(UPSERT_POSTGRESQL));
                } else if (isMSSqlDB() || isDB2DB()) {
                    preparedStatement = connection.prepareStatement(Util.getDBQuery(UPSERT_MSSQL_DB2));
                } else if (isOracleDB()) {
                    preparedStatement = connection.prepareStatement(Util.getDBQuery(UPSERT_ORACLE));
                }

                if (preparedStatement != null) {
                    preparedStatement.setString(1, jti);
                    if (Util.isTenantIdColumnIsAvailableInIdnOidcAuthTable()) {
                        preparedStatement.setInt(2, tenantId);
                        Timestamp timestamp = new Timestamp(timeCreated);
                        Timestamp expTimestamp = new Timestamp(expTime);
                        preparedStatement.setTimestamp(3, expTimestamp, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                        preparedStatement.setTimestamp(4, timestamp,
                                Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                        if (isOracleDB()) {
                            preparedStatement.setString(5, jti);
                            preparedStatement.setInt(6, tenantId);
                            preparedStatement.setTimestamp(7, expTimestamp,
                                    Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                            preparedStatement.setTimestamp(8, timestamp,
                                    Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                        }
                    } else {
                        Timestamp timestamp = new Timestamp(timeCreated);
                        Timestamp expTimestamp = new Timestamp(expTime);
                        preparedStatement.setTimestamp(2, expTimestamp, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                        preparedStatement.setTimestamp(3, timestamp,
                                Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                        if (isOracleDB()) {
                            preparedStatement.setString(4, jti);
                            preparedStatement.setTimestamp(5, expTimestamp,
                                    Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                            preparedStatement.setTimestamp(6, timestamp,
                                    Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
                        }
                    }
                }
            }
            if (preparedStatement != null) {
                preparedStatement.executeUpdate();
                preparedStatement.close();
                connection.commit();
            }
        } catch (SQLException | DataAccessException e) {
            String error = "Error when storing the JWT ID: " + jti + " with exp: " + expTime;
            if (log.isDebugEnabled()) {
                log.debug(error, e);
            }
            throw new OAuthClientAuthnException("Error occurred while validating the JTI: " + jti + " of the " +
                    "assertion.", OAuth2ErrorCodes.INVALID_REQUEST, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, preparedStatement);
        }
    }
}
