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
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.model.ClientAuthenticationMethodModel;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.JWTAuthenticationConfigurationDAO;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidatorTest.TEST_CLIENT_ID_1;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity.sql"})
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {JWTServiceComponent.class})
@WithKeyStore
public class PrivateKeyJWTClientAuthenticatorTest {

    PrivateKeyJWTClientAuthenticator privateKeyJWTClientAuthenticator;
    @Mock
    HttpServletRequest httpServletRequest;

    OAuthClientAuthnContext oAuthClientAuthnContext =new OAuthClientAuthnContext();

    KeyStore clientKeyStore;
    Key key1;
    String audience;

    @BeforeClass
    public void setUp() throws Exception {

        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        privateKeyJWTClientAuthenticator = new PrivateKeyJWTClientAuthenticator();
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
        assertEquals(received, true, "A valid request refused to authenticate.");
    }

    @Test
    public void testPrivateKeyJWTFlagAdded() throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> assertionType = new ArrayList<>();
        assertionType.add(OAUTH_JWT_BEARER_GRANT_TYPE);
        List<String> assertion = new ArrayList<>();
        assertion.add(buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1, 0));
        bodyContent.put(OAUTH_JWT_ASSERTION, assertion);
        bodyContent.put(OAUTH_JWT_ASSERTION_TYPE, assertionType);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);
        JWTServiceDataHolder.getInstance().setRealmService(realmService);
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("OAuth.OpenIDConnect.IDTokenIssuerID", "http://localhost:9443/oauth2/token");
        WhiteboxImpl.setInternalState(IdentityUtil.class, "configuration", configuration);
        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
        jwtClientAuthenticatorConfig.setEnableTokenReuse(true);
        JWTAuthenticationConfigurationDAO mockDAO = Mockito.mock(JWTAuthenticationConfigurationDAO
                .class);
        Mockito.when(mockDAO.getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(Mockito.anyString()))
                .thenReturn(jwtClientAuthenticatorConfig);
        JWTServiceDataHolder.getInstance()
                .setJWTAuthenticationConfigurationDAO(mockDAO);

        try {
            privateKeyJWTClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                    oAuthClientAuthnContext);
            assertEquals(Constants.AUTHENTICATOR_TYPE_PK_JWT, oAuthClientAuthnContext.getParameter(
                    Constants.AUTHENTICATOR_TYPE_PARAM));
        } catch (OAuthClientAuthnException e) {
            assertEquals(Constants.AUTHENTICATOR_TYPE_PK_JWT, oAuthClientAuthnContext.getParameter(
                    Constants.AUTHENTICATOR_TYPE_PARAM));
        }
    }

    @Test
    public void testGetSupportedClientAuthenticationMethods() {

        List<String> supportedAuthMethods = new ArrayList<>();
        for (ClientAuthenticationMethodModel clientAuthenticationMethodModel : privateKeyJWTClientAuthenticator
                .getSupportedClientAuthenticationMethods()) {
            supportedAuthMethods.add(clientAuthenticationMethodModel.getName());
        }
        Assert.assertTrue(supportedAuthMethods.contains("private_key_jwt"));
        assertEquals(supportedAuthMethods.size(), 1);
    }
}
