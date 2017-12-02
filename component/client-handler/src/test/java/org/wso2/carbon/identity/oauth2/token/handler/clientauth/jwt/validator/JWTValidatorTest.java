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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator;

import org.mockito.Mockito;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.common.testng.*;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;

import java.security.KeyStore;
import java.util.concurrent.ConcurrentHashMap;

import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.assertNull;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {JWTServiceComponent.class})
@WithKeyStore
public class JWTValidatorTest {

    public static final String TEST_CLIENT_ID_1 = "KrVLov4Bl3natUksF2HmWsdw684a";
    public static final String TEST_SECRET_1 = "testSecret1";
    private JWTValidator testClass;
    private KeyStore clientKeyStore;
    private KeyStore serverKeyStore;

    @BeforeClass
    public void setUp() throws Exception {
        testClass = new JWTValidator(60, true, true, null, null, null, null);
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));
        serverKeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));

    }

    public void testAuthenticateTokenRequest() throws Exception {

    }

    public void testValidateCustomClaims() throws Exception {

    }

    public void testCheckJwtInDataBase() throws Exception {

    }

    @Test()
    public void testGetCertificate() throws Exception {
        KeyStoreManager keyStoreManager = Mockito.mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(serverKeyStore);
        assertNotNull(testClass.getCertificate(SUPER_TENANT_DOMAIN_NAME, TEST_CLIENT_ID_1, "SP"));
    }

    @Test()
    public void testGetCertificateNonExistingAlias() throws Exception {
        KeyStoreManager keyStoreManager = Mockito.mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(clientKeyStore);
        assertNull(testClass.getCertificate(SUPER_TENANT_DOMAIN_NAME, TEST_CLIENT_ID_1, "SP"));
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetCertificateException() throws Exception {
        testClass.getCertificate(SUPER_TENANT_DOMAIN_NAME, TEST_CLIENT_ID_1, "SP");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetCertificateException2() throws Exception {
        testClass.getCertificate("some-tenant", TEST_CLIENT_ID_1, "SP");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetCertificateException3() throws Exception {
        KeyStoreManager keyStoreManager = Mockito.mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(serverKeyStore);
        KeyStore keyStore = keyStoreManager.getPrimaryKeyStore();
        Mockito.when(keyStore.getCertificate(TEST_CLIENT_ID_1)).thenThrow(new IdentityOAuth2Exception("Identity " +
                "Exception"));
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(serverKeyStore);
        assertNull(testClass.getCertificate(SUPER_TENANT_DOMAIN_NAME, TEST_CLIENT_ID_1, "SP"));
    }

}