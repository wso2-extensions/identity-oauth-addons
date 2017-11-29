
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

public class PrivateKeyJWTStorageManager {

    private static Log log = LogFactory.getLog(PrivateKeyJWTStorageManager.class);

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
                if (count > 0) {
                    isExists = true;
                }
            }
        } catch (SQLException e) {
            String error = "Error when retrieving the JWT ID: " + jti;
            throw new IdentityOAuth2Exception(error,  e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }
        return isExists;
    }

    public void persistJWTIdInDB(String jti, long expTime, long time) throws IdentityOAuth2Exception {
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet rs = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(Constants.SQLQueries.INSERT_JWD_ID);
            preparedStatement.setString(1, jti);
            Timestamp timestamp = new Timestamp(time);
            preparedStatement.setLong(2, expTime);
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
}
