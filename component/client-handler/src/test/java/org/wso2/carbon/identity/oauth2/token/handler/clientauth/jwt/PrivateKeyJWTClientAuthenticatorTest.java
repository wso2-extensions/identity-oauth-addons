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

import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidatorTest.TEST_CLIENT_ID_1;

@PrepareForTest({OAuth2Util.class})
@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity.sql"})
@WithKeyStore
public class PrivateKeyJWTClientAuthenticatorTest extends PowerMockTestCase {

    PrivateKeyJWTClientAuthenticator privateKeyJWTClientAuthenticator;
    @Mock
    HttpServletRequest httpServletRequest;

    OAuthClientAuthnContext oAuthClientAuthnContext =new OAuthClientAuthnContext();

    KeyStore clientKeyStore;
    Key key1;
    public static final String AUDIENCE = "https://localhost:9443/oauth2/token";

    @BeforeClass
    public void setUp() throws Exception {

        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        privateKeyJWTClientAuthenticator = new PrivateKeyJWTClientAuthenticator();
    }

    @Test
    public void testGetClientId() throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertion = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", AUDIENCE, "RSA265", key1, 0));
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
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", AUDIENCE, "RSA265", key1, 0));
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);

        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);
        boolean received = privateKeyJWTClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent,
                oAuthClientAuthnContext);
        assertEquals(received, true, "A valid request refused to authenticate.");

    }

    @Test
    public void testIsValidRegisteredSignatureAlgorithm() throws IdentityOAuth2Exception {

        Map<String, List> bodyContent = getBodyContent();
        ServiceProvider serviceProvider = getServiceProvider("PS256");
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util.getServiceProvider(TEST_CLIENT_ID_1)).thenReturn(serviceProvider);
        PowerMockito.when(OAuth2Util.isFapiConformantApp(Mockito.anyString())).thenReturn(true);
        boolean isRegistered = privateKeyJWTClientAuthenticator.isRegisteredSignatureAlgorithm(httpServletRequest,
                bodyContent, oAuthClientAuthnContext);
        assertTrue(isRegistered, "A valid request refused to authenticate.");
    }

    @Test
    public void testAuthenticateClient() throws IdentityOAuth2Exception {

        Map<String, List> bodyContent = getBodyContent();
        ServiceProvider serviceProvider = getServiceProvider("RS256");
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util.getServiceProvider(TEST_CLIENT_ID_1)).thenReturn(serviceProvider);
        PowerMockito.when(OAuth2Util.isFapiConformantApp(Mockito.anyString())).thenReturn(true);
        boolean isRegistered = privateKeyJWTClientAuthenticator.authenticateClient(httpServletRequest,
                bodyContent, oAuthClientAuthnContext);
        assertFalse(isRegistered, "An invalid request but got authenticated.");
    }

    private Map<String, List> getBodyContent() throws IdentityOAuth2Exception {
        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertion = new ArrayList<>();
        List<String> assertionType = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", AUDIENCE, "PS256", key1, 0));
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);
        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);
        return bodyContent;
    }

    private ServiceProvider getServiceProvider(String alg) {
        ServiceProvider serviceProvider = new ServiceProvider();
        ServiceProviderProperty signingAlgSpProperty = new ServiceProviderProperty();
        signingAlgSpProperty.setName(Constants.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
        signingAlgSpProperty.setValue(alg);
        ServiceProviderProperty fapiAppSpProperty = new ServiceProviderProperty();
        fapiAppSpProperty.setName(OAuthConstants.IS_FAPI_CONFORMANT_APP);
        fapiAppSpProperty.setValue("true");
        serviceProvider.setSpProperties(new ServiceProviderProperty[]{signingAlgSpProperty, fapiAppSpProperty});
        return serviceProvider;
    }
}
