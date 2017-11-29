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

import org.apache.commons.codec.binary.Base64;
import org.mockito.Mockito;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.common.testng.*;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;


@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity.sql"})
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {ApplicationManagementServiceComponentHolder.class})
@WithKeyStore
public class PrivateKeyJWTClientAuthHandlerTest {

    public static final String TEST_CLIENT_ID_1 = "KrVLov4Bl3natUksF2HmWsdw684a";
    public static final String TEST_SECRET_1 = "testSecret1";
    private PrivateKeyJWTClientAuthHandler testclass = new PrivateKeyJWTClientAuthHandler();
    private FederatedAuthenticatorConfig oauthConfig;
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig;

    private KeyStore clientKeyStore;
    private KeyStore serverKeyStore;
    private String CERTIFICATE = "MIIDVzCCAj+gAwIBAgIEN+6m4zANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJGUjEMMAoGA1UE\n" +
            "CBMDTVBMMQwwCgYDVQQHEwNNUEwxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsTBHRlc3QxEzARBgNV\n" +
            "BAMMCioudGVzdC5jb20wHhcNMTcxMTIzMTI1MDEyWhcNNDcxMTE2MTI1MDEyWjBcMQswCQYDVQQG\n" +
            "EwJGUjEMMAoGA1UECBMDTVBMMQwwCgYDVQQHEwNNUEwxDTALBgNVBAoTBHRlc3QxDTALBgNVBAsT\n" +
            "BHRlc3QxEzARBgNVBAMMCioudGVzdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
            "AQCITPQCt3fPuVWCLFBnPfslWAIrh8H/sEx+I/mCscfAGMzBr/aKgtSr+6fcCvJgpj31D9Lp5ZY+\n" +
            "WbpccxeLDDaV4hwAx8P1yi+0xwip8x5UIzjRcJ+n5E/9rjev3QnbynaFzgieyE784BfvO/4fgVTQ\n" +
            "hAE4ZGdqbm1nD0Ic1qptOs7WCXMyjBy5JvqOD74HD7vSOwC4ySFVTOC8ENyF9i9gtx25+zH2FreJ\n" +
            "gHkmLoiEUJMoCZ+ShH0tl8LoFVM5CTxWb6iNj28bYqgLAjVkOSO1G2GbOV8XzdaIj1m5ECksdQqf\n" +
            "770UDjrGNM5VmzxMDDEKjB6/qhs6q4HeCZuzicbhAgMBAAGjITAfMB0GA1UdDgQWBBTiJxYPvJcZ\n" +
            "3XlcnaZVFpOFbfj5ujANBgkqhkiG9w0BAQsFAAOCAQEAfbtzvY81vgNz5M1MwG78KdOEiSwNU6/y\n" +
            "RqWBUsa5aB7w6vFdsgZ1D/J2v5VnVwXHrmWHCiIkXk70kD0gFJhDa4gNPsuAs0acMcZumEzjY8P2\n" +
            "0s4LP5TOfCHraPMElFWmHwZI4/SaR5xGgzRxehqJ+KP6UKHWkhf/NP+SBetVAdXfNFp/hO+67XFe\n" +
            "aFr3vXKegooXrm58vCvg/J1nJapbhWiTDvgeNF5EhnLDNs04oBsOcjzrGDihv4F+Vl1yx/RelAwv\n" +
            "W/bQM+jWUllR4Qpwx6R1mVy3pFRl0+4npUr17XOGEoP9Xm/5kMvsiNOTqryR5p3xEPBQcXBJES8K\n" +
            "oQon6A==";

    @BeforeClass
    public void setUp() throws Exception {
        //mock keystore and keys
        Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
        publicCerts.put(SUPER_TENANT_ID, ReadCertStoreSampleUtil.createKeyStore(getClass())
                .getCertificate("wso2carbon"));
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));
        serverKeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));

        KeyStoreManager keyStoreManager = Mockito.mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.decodeBase64(CERTIFICATE)));
        Mockito.when(keyStoreManager.getDefaultPrimaryCertificate()).thenReturn(cert);
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(serverKeyStore);
        Mockito.when(keyStoreManager.getKeyStore("wso2carbon.jks")).thenReturn(serverKeyStore);

        JWTTestUtil.createApplication(TEST_CLIENT_ID_1, TEST_SECRET_1, SUPER_TENANT_ID);
//        JWTTestUtil.createApplication(TEST_CLIENT_ID_2, TEST_SECRET_2, SUPER_TENANT_ID);

        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);
        JWTServiceDataHolder.getInstance().setRealmService(realmService);

        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);

    }

    @DataProvider(name = "provideOAuthTokenReqMessageContext")
    public Object[][] createOAuthTokenReqMessageContext() {

        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO1 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO2 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO3 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO4 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO5 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO6 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO7 = new OAuth2AccessTokenReqDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO8 = new OAuth2AccessTokenReqDTO();

        oauth2AccessTokenReqDTO1.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO1.setClientSecret(TEST_SECRET_1);
        oauth2AccessTokenReqDTO2.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO3.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO4.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO5.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO6.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO7.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO8.setClientId(TEST_CLIENT_ID_1);

        oauth2AccessTokenReqDTO1.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO2.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO3.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO4.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO5.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO6.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO7.setGrantType("authorization_code");
        oauth2AccessTokenReqDTO8.setGrantType("authorization_code");

        Properties properties1 = new Properties();
        Properties properties2 = new Properties();
        Properties properties3 = new Properties();
        Properties properties4 = new Properties();

        properties1.setProperty("StrictClientCredentialValidation", "false");
        properties1.setProperty("EnableCacheForJTI", "true");
        properties1.setProperty("JwtValidityPeriod", "30");

        properties2.setProperty("StrictClientCredentialValidation", "true");

        properties3.setProperty("StrictClientCredentialValidation", "false");
        properties4.setProperty("StrictClientCredentialValidation", "false");

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext1 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext2 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext3 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext4 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext5 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext6 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext7 = buildOAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext8 = buildOAuth2AccessTokenReqDTO();

        try {
            Key key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
            String audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);

            String privateKeyJWT1 = buildJWT(oauth2AccessTokenReqDTO1.getClientId(), oauth2AccessTokenReqDTO1.getClientId
                    (), "1000", audience, "RSA265", key1, 0);
            String privateKeyJWT2 = buildJWT(oauth2AccessTokenReqDTO1.getClientId(),
                    oauth2AccessTokenReqDTO1.getClientId(), "1000", audience, "RSA265", key1, 6000000);
            String privateKeyJWT3 = buildJWT("some-issuer",
                    oauth2AccessTokenReqDTO1.getClientId(), "1001", audience, "RSA265", key1, 6000000);
            String privateKeyJWT4 = buildJWT(oauth2AccessTokenReqDTO1.getClientId(),
                    "some-client-id", "1002", audience, "RSA265", key1, 0);
            String privateKeyJWT5 = buildJWT(oauth2AccessTokenReqDTO1.getClientId(),
                    oauth2AccessTokenReqDTO1.getClientId(), "1000", audience, "RSA265", key1, 0);
            String privateKeyJWT6 = "some-string";
            String privateKeyJWT7 = buildJWT(oauth2AccessTokenReqDTO1.getClientId(),
                    oauth2AccessTokenReqDTO1.getClientId(), "2000", audience, "RSA265", key1, 0);
            String privateKeyJWT8 = buildJWT(oauth2AccessTokenReqDTO1.getClientId() ,
                    oauth2AccessTokenReqDTO1.getClientId(), null , null, "RSA265", key1, 0);

            RequestParameter[] requestParameters1 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT1)};
            RequestParameter[] requestParameters2 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT2)};
            RequestParameter[] requestParameters3 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT3)};
            RequestParameter[] requestParameters4 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT4)};
            RequestParameter[] requestParameters5 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT5)};
            RequestParameter[] requestParameters6 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT6)};
            RequestParameter[] requestParameters7 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT7)};
            RequestParameter[] requestParameters8 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), new RequestParameter("client_assertion",
                    privateKeyJWT8)};

            oauth2AccessTokenReqDTO1.setRequestParameters(requestParameters1);
            oAuthTokenReqMessageContext1.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters1);

            oauth2AccessTokenReqDTO2.setRequestParameters(requestParameters2);
            oAuthTokenReqMessageContext2.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters2);

            oauth2AccessTokenReqDTO3.setRequestParameters(requestParameters3);
            oAuthTokenReqMessageContext3.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters3);

            oauth2AccessTokenReqDTO4.setRequestParameters(requestParameters4);
            oAuthTokenReqMessageContext4.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters4);

            oauth2AccessTokenReqDTO5.setRequestParameters(requestParameters5);
            oAuthTokenReqMessageContext5.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters5);

            oauth2AccessTokenReqDTO6.setRequestParameters(requestParameters6);
            oAuthTokenReqMessageContext6.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters6);

            oauth2AccessTokenReqDTO7.setRequestParameters(requestParameters7);
            oAuthTokenReqMessageContext7.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters7);

            oauth2AccessTokenReqDTO8.setRequestParameters(requestParameters8);
            oAuthTokenReqMessageContext8.getOauth2AccessTokenReqDTO().setRequestParameters(requestParameters8);

            OAuthTokenReqMessageContext tokReqMsgCtx1 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO1);
            OAuthTokenReqMessageContext tokReqMsgCtx2 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO2);
            OAuthTokenReqMessageContext tokReqMsgCtx3 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO3);
            OAuthTokenReqMessageContext tokReqMsgCtx4 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO4);
            OAuthTokenReqMessageContext tokReqMsgCtx5 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO5);
            OAuthTokenReqMessageContext tokReqMsgCtx6 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO6);
            OAuthTokenReqMessageContext tokReqMsgCtx7 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO7);
            OAuthTokenReqMessageContext tokReqMsgCtx8 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO8);

            return new Object[][]{
                    {tokReqMsgCtx1, true, properties1, true},
                    {tokReqMsgCtx2, true, properties2, false},
                    {tokReqMsgCtx3, true, properties3, false},
                    {tokReqMsgCtx4, true, properties3, false},
                    {tokReqMsgCtx5, true, properties3, false},
                    {tokReqMsgCtx6, true, properties3, false},
                    {tokReqMsgCtx7, true, properties3, false},
                    {tokReqMsgCtx8, true, properties3, false}
            };
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IdentityOAuth2Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @DataProvider(name = "provideOAuthTokenReqMessageContextForSAMLBearer")
    public Object[][] createOAuthTokenReqMessageContextForSAMLBearer() {

        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO2 = new OAuth2AccessTokenReqDTO();
        oauth2AccessTokenReqDTO2.setClientId(TEST_CLIENT_ID_1);
        oauth2AccessTokenReqDTO2.setGrantType(String.valueOf(org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER));

        Properties properties2 = new Properties();

        properties2.setProperty("StrictClientCredentialValidation", "false");

        RequestParameter[] requestParameters2 = new RequestParameter[]{};
        oauth2AccessTokenReqDTO2.setRequestParameters(requestParameters2);

        OAuthTokenReqMessageContext tokReqMsgCtx2 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO2);

        return new Object[][]{
                {tokReqMsgCtx2, true, properties2}
        };
    }

    public void testInit() throws Exception {

    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContext")
    public void testCanAuthenticate(Object oAuthTokenReqMessageContext, boolean expected,
                                    Object properties, boolean isAuthenticated) throws Exception {
        testclass.init((Properties) properties);
        assertEquals(testclass.canAuthenticate((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expected);

    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContextForSAMLBearer")
    public void testCanAuthenticateForSAMLBearer(Object oAuthTokenReqMessageContext, boolean expectedValue,
                                                 Object properties) throws Exception {
        testclass.init((Properties) properties);
        assertEquals(testclass.canAuthenticate((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expectedValue);

    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContext")
    public void testAuthenticateClient(Object oAuthTokenReqMessageContext, boolean canAuthenticate,
                                       Object properties, boolean expectedValue)
            throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

        testclass.init((Properties) properties);
        assertEquals(testclass.authenticateClient((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expectedValue);
    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContextForSAMLBearer")
    public void testAuthenticateClientForSAMLBearer(Object oAuthTokenReqMessageContext, boolean expectedValue,
                                                    Object properties)
            throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

        testclass.init((Properties) properties);
        assertEquals(testclass.authenticateClient((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expectedValue);
    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContext", dependsOnMethods = {"testAuthenticateClient"})
    public void testAuthenticateClientWithSameJWT(Object oAuthTokenReqMessageContext, boolean canAuthenticate,
                                                  Object properties, boolean isAuthenticate)
            throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {
        assertEquals(testclass.authenticateClient((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                false);
    }

    public void testGetCertificate() throws Exception {

    }

    public void testValidateCustomClaims() throws Exception {

    }

    private OAuthTokenReqMessageContext buildOAuth2AccessTokenReqDTO() {
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(
                oAuth2AccessTokenReqDTO);
        return oAuthTokenReqMessageContext;
    }

}