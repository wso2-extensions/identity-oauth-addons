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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTStorageManager;

import java.sql.Connection;
import java.sql.DriverManager;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class JWTStorageManagerTest {

    private JWTStorageManager jwtStorageManager;
    private MockedStatic<IdentityDatabaseUtil> mockedIdentityDatabaseUtil;

    @BeforeClass
    public void setUpClass() throws Exception {
        jwtStorageManager = new JWTStorageManager();
    }

    @BeforeMethod
    public void setUpMethod() throws Exception {
        // 1. Initialize an in-memory database and create the required table
        try (Connection initConn = DriverManager.getConnection("jdbc:h2:mem:jwt_storage_db;DB_CLOSE_DELAY=-1", "sa", "")) {
            initConn.createStatement().execute("CREATE TABLE IF NOT EXISTS IDN_OIDC_JTI (JWT_ID VARCHAR(255), EXP_TIME TIMESTAMP, TIME_CREATED TIMESTAMP, TENANT_ID INTEGER, PRIMARY KEY (JWT_ID))");
            
            // 2. Pre-populate JTI "2000" which is expected to exist by the tests
            initConn.createStatement().execute("INSERT INTO IDN_OIDC_JTI (JWT_ID, EXP_TIME, TIME_CREATED, TENANT_ID) VALUES ('2000', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, -1234)");
        }

        // 3. Mock IdentityDatabaseUtil to return a fresh connection to our H2 DB on every call
        mockedIdentityDatabaseUtil = Mockito.mockStatic(IdentityDatabaseUtil.class, Mockito.CALLS_REAL_METHODS);
        mockedIdentityDatabaseUtil.when(IdentityDatabaseUtil::getDBConnection).thenAnswer(invocation -> 
            DriverManager.getConnection("jdbc:h2:mem:jwt_storage_db;DB_CLOSE_DELAY=-1", "sa", "")
        );
        mockedIdentityDatabaseUtil.when(() -> IdentityDatabaseUtil.getDBConnection(anyBoolean())).thenAnswer(invocation -> 
            DriverManager.getConnection("jdbc:h2:mem:jwt_storage_db;DB_CLOSE_DELAY=-1", "sa", "")
        );
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
        // Strictly required to close static mocks to prevent test pollution
        if (mockedIdentityDatabaseUtil != null) {
            mockedIdentityDatabaseUtil.close();
        }
        
        // Drop the table after each test to ensure complete isolation between runs
        try (Connection clearConn = DriverManager.getConnection("jdbc:h2:mem:jwt_storage_db;DB_CLOSE_DELAY=-1", "sa", "")) {
            clearConn.createStatement().execute("DROP TABLE IF EXISTS IDN_OIDC_JTI");
        }
    }

    @Test()
    public void testIsJTIExistsInDB() throws Exception {
        assertTrue(jwtStorageManager.isJTIExistsInDB("2000"));
    }

    @Test()
    public void testGetJwtFromDB() throws Exception {
        assertNotNull(jwtStorageManager.getJwtFromDB("2000"));
    }

    @Test()
    public void testPersistJWTIdInDB() throws Exception {
        jwtStorageManager.persistJWTIdInDB("2004", 10000000, 10000000);
    }

    @Test(expectedExceptions = OAuthClientAuthnException.class)
    public void testPersistJWTIdInDBExceptionCase() throws Exception {
        // This will throw the exception because "2000" is already inserted in our @BeforeMethod
        jwtStorageManager.persistJWTIdInDB("2000", 10000000, 10000000);
    }
}