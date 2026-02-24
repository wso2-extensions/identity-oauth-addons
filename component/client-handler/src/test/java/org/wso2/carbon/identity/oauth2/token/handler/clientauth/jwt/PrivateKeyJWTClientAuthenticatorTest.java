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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidatorTest.TEST_CLIENT_ID_1;

public class PrivateKeyJWTClientAuthenticatorTest {

    private PrivateKeyJWTClientAuthenticator privateKeyJWTClientAuthenticator;
    private HttpServletRequest httpServletRequest;
    private OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();

    private KeyStore clientKeyStore;
    private Key key1;
    private String audience;
    
    // Static mock reference to manage lifecycle between tests
    private MockedStatic<IdentityUtil> mockedIdentityUtil;

    @BeforeClass
    public void setUpClass() throws Exception {
        // Ensure carbon.home is set to prevent NullPointerException when loading the keystore
        String carbonHome = System.getProperty(CarbonBaseConstants.CARBON_HOME);
        if (carbonHome == null) {
            carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
            System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        }

        // Load the Keystore once for the whole class
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon", carbonHome);
        key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
    }

    @BeforeMethod
    public void setUpMethod() {
        // Initialize the mocked HTTP request natively without requiring a Mockito test runner
        httpServletRequest = Mockito.mock(HttpServletRequest.class);
        privateKeyJWTClientAuthenticator = new PrivateKeyJWTClientAuthenticator();

        // Intercept IdentityUtil to bypass OSGi ConfigurationContextService NPEs
        mockedIdentityUtil = Mockito.mockStatic(IdentityUtil.class, Mockito.CALLS_REAL_METHODS);
        mockedIdentityUtil.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn("https://localhost:9443/oauth2/token");

        // Fetch audience securely while the static mock is active
        audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
    }

    @AfterMethod
    public void tearDownMethod() {
        // Always close static mocks after each test to prevent memory leaks and test pollution
        if (mockedIdentityUtil != null) {
            mockedIdentityUtil.close();
        }
    }

    @Test
    public void testGetClientId() throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertion = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1, 0));
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);
        
        String clientId = privateKeyJWTClientAuthenticator.getClientId(httpServletRequest, bodyContent,
                oAuthClientAuthnContext);
                
        assertEquals(clientId, "KrVLov4Bl3natUksF2HmWsdw684a", "The expected client id is the jwt subject.");
    }

    @Test
    public void testcanAuthenticate() throws IdentityOAuth2Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertion = new ArrayList<>();
        List<String> assertionType = new ArrayList<>();
        
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1, 0));
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);

        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);
        
        boolean received = privateKeyJWTClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent,
                oAuthClientAuthnContext);
                
        assertTrue(received, "A valid request refused to authenticate.");
    }
}