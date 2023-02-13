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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage;

import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.core.util.JdbcUtils;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTStorageManager;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.List;

import static org.testng.Assert.assertEquals;
import java.sql.Connection;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.closeH2Base;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.initiateH2Base;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.spyConnection;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.Util.checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable;


@PrepareForTest({IdentityUtil.class, JdbcUtils.class, IdentityDatabaseUtil.class, FrameworkUtils.class})
public class JWTStorageManagerTest extends PowerMockIdentityBaseTest {

    private JWTStorageManager JWTStorageManager;
    private Connection spyConnection;


    @BeforeClass
    public void setUp() throws Exception {

        initiateH2Base();
        JWTStorageManager = new JWTStorageManager();

    }

    @BeforeMethod
    public void init() throws Exception {

        mockStatic(IdentityDatabaseUtil.class);
        spyConnection = spyConnection(JWTTestUtil.getConnection());
        Mockito.when(IdentityDatabaseUtil.getDBConnection()).thenReturn(spyConnection);
        mockStatic(JdbcUtils.class);
        mockStatic(FrameworkUtils.class);
        Mockito.when(FrameworkUtils.isTableColumnExists(Constants.SQLQueries.IDN_OIDC_JTI,
                Constants.SQLQueries.TENANT_ID)).thenReturn(true);
        checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable();

    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base();
    }

    @Test()
    public void testPersistJWTIdInDB() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(true);
        JWTStorageManager.persistJWTIdInDB("2023", -1234, 10000000, 10000000);
    }

    @Test(expectedExceptions = OAuthClientAuthnException.class)
    public void testPersistJWTIdInDBExceptionCase() throws Exception {

        JWTStorageManager.persistJWTIdInDB("2000", -1234, 10000000, 10000000);
    }

    @Test()
    public void testGetJwtsFromDB() throws Exception {

        List<JWTEntry> jwtEntryList = JWTStorageManager.getJwtsFromDB("10010010", 1);
        assertNotNull(jwtEntryList);
        JWTEntry jwtEntry = jwtEntryList.get(0);
        assertEquals(1, jwtEntry.getTenantId());
    }

    @Test()
    public void testPersistJWTIdInDBWithoutTokenReuse() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(false);
        when(JdbcUtils.isH2DB()).thenReturn(true);
        when(JdbcUtils.isOracleDB()).thenReturn(false);
        // Insert a JTI entry with Expired Date.
        JWTStorageManager.persistJWTIdInDB("2023", 12, 10000000, 10000000);
        when(JdbcUtils.isH2DB()).thenReturn(true);
        when(JdbcUtils.isOracleDB()).thenReturn(false);
        // Update a JTI entry again.
        JWTStorageManager.persistJWTIdInDB("2023", 12, 10001000, 10000100);
    }

    @Test(dependsOnMethods = {"testPersistJWTIdInDBWithoutTokenReuse"})
    public void testUpdatedJTIEntry() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(false);
        JWTEntry jwtEntry = JWTStorageManager.getJwtsFromDB("2023",12).get(0);
        assertEquals(jwtEntry.getExp(), 10001000);
        assertEquals(jwtEntry.getCreatedTime(), 10000100);
    }
}
