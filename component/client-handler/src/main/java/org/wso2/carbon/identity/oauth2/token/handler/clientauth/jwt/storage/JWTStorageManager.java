
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;

import java.sql.*;
import java.util.*;

/**
 * JWT token persistence is managed by JWTStorageManager
 * It saved JWTEntry instances in Identity Database.
 */
public class JWTStorageManager {
    private static final Log log = LogFactory.getLog(JWTStorageManager.class);

    /**
     * Inner class to implement saving JWT entries using a different thread
     */
    class JWTIDPersistingThread implements Runnable {
        long issuedTime;
        String jti;

        long expiryTime;

        public JWTIDPersistingThread(String jti, long expiryTime, long issuedTime) {
            super();
            this.expiryTime = expiryTime;
            this.jti = jti;
            this.issuedTime = issuedTime;
        }
        @Override
        public void run() {
            try {
                persistJWTIdInDB(jti, expiryTime, issuedTime);
                if (log.isDebugEnabled()) {
                    log.debug("JWT Token with jti:" + jti + " was added to the storage successfully");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Error occurred while persisting JWT ID:" + jti, e);
            }
        }

    }

    /**
     * check whether a JWT Entry with given jti exists in the DB
     * @param jti JWT TOKEN ID
     * @return true if an entry is found
     * @throws IdentityOAuth2Exception when exception occures
     */
    public boolean isJTIExistsInDB(String jti) throws IdentityOAuth2Exception {
        Connection dbConnection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        boolean isExists = false;
        ResultSet rs = null;
        try {
            prepStmt = dbConnection.prepareStatement(Constants.SQLQueries.GET_JWT_ID);
            prepStmt.setString(1, jti);
            rs = prepStmt.executeQuery();
            int count = 0;
            if (rs.next()) {
                count = rs.getInt(1);
            }
            if (count > 0) {
                isExists = true;
            }
        } catch (SQLException e) {
            String error = "Error when retrieving the JWT ID: " + jti;
            throw new IdentityOAuth2Exception(error,  e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }
        return isExists;
    }

    /**
     * To retrieve a JWT Entry with given jti if, exists in the DB
     * @param jti JWT TOKEN ID
     * @return JWT entry if found, null otherwise
     * @throws IdentityOAuth2Exception when exception occurs
     */
    public JWTEntry getJwtFromDB(String jti) throws IdentityOAuth2Exception {
        Connection dbConnection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        JWTEntry jwtEntry= null;
        try {
            prepStmt = dbConnection.prepareStatement(Constants.SQLQueries.GET_JWT);
            prepStmt.setString(1, jti);
            rs = prepStmt.executeQuery();
            if (rs.next()) {
                long exp = rs.getTime(1, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))).getTime();
                long created = rs.getTime(2, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC))).getTime();
                jwtEntry = new JWTEntry(exp, created);
            }
        } catch (SQLException e) {
            String error = "Error when retrieving the JWT ID: " + jti;
            throw new IdentityOAuth2Exception(error,  e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }
        return jwtEntry;
    }

    /**
     * Save JWT entry to database
     * @param jti JWT TOKEN ID
     * @param expTime expiration time
     * @param created created time
     * @throws IdentityOAuth2Exception
     */
    public void persistJWTIdInDB(String jti, long expTime, long created) throws IdentityOAuth2Exception {
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet rs = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(Constants.SQLQueries.INSERT_JWD_ID);
            preparedStatement.setString(1, jti);
            Timestamp timestamp = new Timestamp(created);
            Timestamp expTimestamp = new Timestamp(expTime);
            preparedStatement.setTimestamp(2, expTimestamp, Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
            preparedStatement.setTimestamp(3, timestamp,
                    Calendar.getInstance(TimeZone.getTimeZone(Constants.UTC)));
            preparedStatement.executeUpdate();
            preparedStatement.close();
            connection.commit();
        } catch (SQLException e) {
            String error = "Error when storing the JWT ID: " + jti + " with exp: " +
                    expTime;
            throw new IdentityOAuth2Exception(error, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, preparedStatement);
        }
    }

    /**
     * Public method to request saving a JWT information to DB
     * Perform persistence task via a new thread
     * @param jti
     * @param expiryTime
     * @param issuedTime
     */
    public void persistJwt(final String jti, long expiryTime, long issuedTime){
        new Thread(new JWTIDPersistingThread(jti, expiryTime, issuedTime)).start();
    }
}
