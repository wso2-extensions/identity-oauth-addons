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

import com.nimbusds.jose.JWSAlgorithm;
import org.apache.commons.codec.binary.Base64;
import org.mockito.Mockito;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidator;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;


@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity.sql"})
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {JWTServiceComponent.class})
@WithKeyStore
public class PrivateKeyJWTClientAuthHandlerTest {

    public static final String TEST_CLIENT_ID_1 = "KrVLov4Bl3natUksF2HmWsdw684a";
    public static final String TEST_SECRET_1 = "testSecret1";
    public static final String OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private KeyStore clientKeyStore;
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
        KeyStore serverKeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon", System.getProperty(CarbonBaseConstants.CARBON_HOME));

        KeyStoreManager keyStoreManager = Mockito.mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put("-1234", keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.decodeBase64(CERTIFICATE)));
        Mockito.when(keyStoreManager.getDefaultPrimaryCertificate()).thenReturn(cert);
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(serverKeyStore);
        Mockito.when(keyStoreManager.getKeyStore("wso2carbon.jks")).thenReturn(serverKeyStore);

        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);
        JWTServiceDataHolder.getInstance().setRealmService(realmService);
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);

        JWTTestUtil.createApplication(TEST_CLIENT_ID_1, TEST_SECRET_1, SUPER_TENANT_ID);

    }

    @DataProvider(name = "provideOAuthTokenReqMessageContext")
    public Object[][] createOAuthTokenReqMessageContext() {

        Properties properties1 = new Properties();
        Properties properties2 = new Properties();
        Properties properties3 = new Properties();
        Properties properties4 = new Properties();
        Properties properties5 = new Properties();

        properties1.setProperty("StrictClientCredentialValidation", "false");
        properties1.setProperty("EnableCacheForJTI", "true");
        properties1.setProperty("JwtValidityPeriod", "30");

        properties2.setProperty("StrictClientCredentialValidation", "true");

        properties3.setProperty("StrictClientCredentialValidation", "false");
        properties4.setProperty("StrictClientCredentialValidation", "false");

        properties5.setProperty("PreventTokenReuse", "false");

        try {
            Key key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
            String audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);

            String privateKeyJWT1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", key1, 0);
            String privateKeyJWT2 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", key1,
                    6000000);
            String privateKeyJWT3 = buildJWT("some-issuer", TEST_CLIENT_ID_1, "1001", audience, "RSA265", key1,
                    6000000);
            String privateKeyJWT4 = buildJWT(TEST_CLIENT_ID_1, "some-client-id", "1002", audience, "RSA265", key1, 0);
            String privateKeyJWT5 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", key1, 0);
            String privateKeyJWT6 = "some-string";
            String privateKeyJWT7 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2000", audience, "RSA265", key1, 0);
            String privateKeyJWT8 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, null, audience, "RSA265", key1, 0);
            String privateKeyJWT9 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1002", audience, "RSA265", key1,
                    Calendar.getInstance().getTimeInMillis());
            String privateKeyJWT10 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1003", audience,
                    JWSAlgorithm.NONE.getName(), key1, 0);
            String privateKeyJWT11 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1004", audience, "RSA265", key1,
                    0, 0, 1000000000);

            String privateKeyJWT12 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1005", audience, "RSA265", key1, 0);
            String privateKeyJWT13 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience, "RSA265", key1, 0);
            String privateKeyJWT15 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1006", audience, "RSA265", key1,
                    600000000);

            String privateKeyJWT16 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1007", audience,
                    JWSAlgorithm.NONE.getName(), key1, 0);
            String hsSignedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                    ".eyJzdWIiOiJLclZMb3Y0QmwzbmF0VWtzRjJIbVdzZHc2ODRhIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzdWVyIjoiS3JWTG92NEJsM25hdFVrc0YySG1Xc2R3Njg0YSIsImp0aSI6MTAwOCwiZXhwIjoiMjU1NDQ0MDEzMjAwMCIsImF1ZCI6WyJzb21lLWF1ZGllbmNlIl19.m0RrVUrZHr1M7R4I_4dzpoWD8jNA2fKkOadEsFg9Wj4";

            OAuthTokenReqMessageContext tokReqMsgCtx1 = getOAuthTokenReqMessageContext(privateKeyJWT1);
            OAuthTokenReqMessageContext tokReqMsgCtx2 = getOAuthTokenReqMessageContext(privateKeyJWT2);
            OAuthTokenReqMessageContext tokReqMsgCtx3 = getOAuthTokenReqMessageContext(privateKeyJWT3);
            OAuthTokenReqMessageContext tokReqMsgCtx4 = getOAuthTokenReqMessageContext(privateKeyJWT4);
            OAuthTokenReqMessageContext tokReqMsgCtx5 = getOAuthTokenReqMessageContext(privateKeyJWT5);
            OAuthTokenReqMessageContext tokReqMsgCtx6 = getOAuthTokenReqMessageContext(privateKeyJWT6);
            OAuthTokenReqMessageContext tokReqMsgCtx7 = getOAuthTokenReqMessageContext(privateKeyJWT7);
            OAuthTokenReqMessageContext tokReqMsgCtx8 = getOAuthTokenReqMessageContext(privateKeyJWT8);
            OAuthTokenReqMessageContext tokReqMsgCtx9 = getOAuthTokenReqMessageContext(privateKeyJWT9);
            OAuthTokenReqMessageContext tokReqMsgCtx10 = getOAuthTokenReqMessageContext(privateKeyJWT10);
            OAuthTokenReqMessageContext tokReqMsgCtx11 = getOAuthTokenReqMessageContext(privateKeyJWT11);
            OAuthTokenReqMessageContext tokReqMsgCtx12 = getOAuthTokenReqMessageContext(privateKeyJWT12);
            OAuthTokenReqMessageContext tokReqMsgCtx13 = getOAuthTokenReqMessageContext(privateKeyJWT13);
            OAuthTokenReqMessageContext tokReqMsgCtx14 = getOAuthTokenReqMessageContext(null);
            OAuthTokenReqMessageContext tokReqMsgCtx15 = getOAuthTokenReqMessageContext(privateKeyJWT15);
            OAuthTokenReqMessageContext tokReqMsgCtx16 = getOAuthTokenReqMessageContext(privateKeyJWT16);
            OAuthTokenReqMessageContext tokReqMsgCtx17 = getOAuthTokenReqMessageContext(hsSignedJWT);

            return new Object[][]{
                    {tokReqMsgCtx1, true, properties1, true, "Correct authentication request is failed."},
                    {tokReqMsgCtx2, true, properties1, false, "JWT replay with preventTokenReuse enabled is not " +
                            "failed. "},
                    {tokReqMsgCtx3, true, properties3, false, "JWT with Invalid field Issuer must be fail."},
                    {tokReqMsgCtx4, true, properties3, false, "Request with non existing SP client-id should fail."},
                    {tokReqMsgCtx5, true, properties3, false, "JWT replay with preventTokenReuse disabled but " +
                            "not-expired is not failed"},
                    {tokReqMsgCtx6, true, properties3, false, "Invalid JWT token validation should fail."},
                    {tokReqMsgCtx7, true, properties3, false, "JWT persisted in database with preventTokenReuse " +
                            "enabled is not failed."},
                    {tokReqMsgCtx8, true, properties3, false, "JWT with jti null is not failed"},
                    {tokReqMsgCtx9, true, properties1, false, "JWT persisted in database with preventTokenReuse " +
                            "disabled is not failed."},
                    {tokReqMsgCtx10, true, properties1, false, "Non signed JWT should be failed."},
                    {tokReqMsgCtx11, true, properties1, false, ""},
                    {tokReqMsgCtx12, true, properties5, true, ""},
                    {tokReqMsgCtx12, true, properties5, false, ""},
                    {tokReqMsgCtx13, true, properties1, false, ""},
                    {tokReqMsgCtx14, false, properties1, false, ""},
                    {tokReqMsgCtx15, true, properties1, false, ""},
                    {tokReqMsgCtx16, true, properties1, false, ""},
                    {tokReqMsgCtx17, true, properties1, false, ""}
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

    @DataProvider(name = "provideInvalidOAuthTokenReqMessageContext")
    public Object[][] createInvalidOAuthTokenReqMessageContext() {

        Properties properties1 = new Properties();
        properties1.setProperty("StrictClientCredentialValidation", "false");
        properties1.setProperty("EnableCacheForJTI", "true");
        properties1.setProperty("JwtValidityPeriod", "30");

        try {
            Key key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
            String audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);

            String privateKeyJWT1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "1000", audience, "RSA265", key1, 0);

            OAuthTokenReqMessageContext tokReqMsgCtx1 = getOAuthTokenReqMessageContext(privateKeyJWT1);
            OAuthTokenReqMessageContext tokReqMsgCtx2 = getOAuthTokenReqMessageContext(privateKeyJWT1,
                    "some-assertion-type");
            OAuthTokenReqMessageContext tokReqMsgCtx3 = getOAuthTokenReqMessageContext(null, null);
            OAuthTokenReqMessageContext tokReqMsgCtx4 = getOAuthTokenReqMessageContext(null,
                    OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER);

            return new Object[][]{
                    {tokReqMsgCtx1, properties1, true, "Correct authentication request is failed."},
                    {tokReqMsgCtx2, properties1, false, "Incorrect assertion type is not " +
                            "failed. "},
                    {tokReqMsgCtx3, properties1, false, "Incorrect Assertion must be fail."},
                    {tokReqMsgCtx4, properties1, false, "Incorrect Assertion Type and Assertion must fail."},
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

    private OAuthTokenReqMessageContext getOAuthTokenReqMessageContext(String clientAssertion) {
        return getOAuthTokenReqMessageContext(clientAssertion, OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER);
    }

    private OAuthTokenReqMessageContext getOAuthTokenReqMessageContext(String clientAssertion,
                                                                       String clientAssertionType) {
        OAuthTokenReqMessageContext tokReqMsgCtx;
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oauth2AccessTokenReqDTO.setGrantType("authorization_code");
        RequestParameter[] requestParameters1 = new RequestParameter[]{new RequestParameter("client_assertion_type",
                clientAssertionType), new RequestParameter("client_assertion",
                clientAssertion)};
        oauth2AccessTokenReqDTO.setRequestParameters(requestParameters1);
        tokReqMsgCtx = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
        return tokReqMsgCtx;
    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContext")
    public void testCanAuthenticate(Object oAuthTokenReqMessageContext, boolean expected,
                                    Object properties, boolean isAuthenticated, String errorMsg) throws Exception {
//        testClass.init((Properties) properties);
        PrivateKeyJWTClientAuthHandler privateKeyJWTClientAuthHandler = new PrivateKeyJWTClientAuthHandler();
        privateKeyJWTClientAuthHandler.init((Properties) properties);
        assertEquals(privateKeyJWTClientAuthHandler.canAuthenticate((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expected, errorMsg);

    }

    @Test(dataProvider = "provideOAuthTokenReqMessageContext")
    public void testAuthenticateClient(Object oAuthTokenReqMessageContext, boolean canAuthenticate,
                                       Object properties, boolean expectedValue, String errorMsg)
            throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

        PrivateKeyJWTClientAuthHandler privateKeyJWTClientAuthHandler = new PrivateKeyJWTClientAuthHandler();
        privateKeyJWTClientAuthHandler.init((Properties) properties);
//        testClass.init((Properties) properties);
        assertEquals(privateKeyJWTClientAuthHandler.authenticateClient((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expectedValue, errorMsg);
    }

    @Test(dataProvider = "provideInvalidOAuthTokenReqMessageContext")
    public void testAuthenticateClientInvalidRequest(Object oAuthTokenReqMessageContext, Object properties,
                                                     boolean expectedValue,
                                                     String errorMsg) throws InvalidOAuthClientException,
            IdentityOAuth2Exception, IdentityOAuthAdminException {

        PrivateKeyJWTClientAuthHandler privateKeyJWTClientAuthHandler = new PrivateKeyJWTClientAuthHandler();
        privateKeyJWTClientAuthHandler.init((Properties) properties);
        assertEquals(privateKeyJWTClientAuthHandler.canAuthenticate((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext),
                expectedValue, errorMsg);
    }

    @Test()
    public void testInit() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("RejectBeforePeriodInMinutes", "30");
        properties.setProperty("PreventTokenReuse", "false");
        properties.setProperty("Audience", "some-audience");
        properties.setProperty("Issuer", "some-issuer");
        properties.setProperty("SubjectField", "some-subject");
        properties.setProperty("EnableCacheForJTI", "true");
        properties.setProperty("SignedBy", "some-signedby-value");
        PrivateKeyJWTClientAuthHandler privateKeyJWTClientAuthHandler = new PrivateKeyJWTClientAuthHandler();
        privateKeyJWTClientAuthHandler.init(properties);
        Field jwtValidatorField = PrivateKeyJWTClientAuthHandler.class.getDeclaredField("jwtValidator");
        jwtValidatorField.setAccessible(true);
        JWTValidator jwtValidator = (JWTValidator) jwtValidatorField.get(privateKeyJWTClientAuthHandler);
        Field field = JWTValidator.class.getDeclaredField("notAcceptBeforeTimeInMins");
        field.setAccessible(true);
        int validityPeriod = (int) field.get(jwtValidator);
        assertEquals(validityPeriod, 30);
        Field fieldPreventTokenReuse = JWTValidator.class.getDeclaredField("preventTokenReuse");
        fieldPreventTokenReuse.setAccessible(true);
        boolean preventTokenReuse = (boolean) fieldPreventTokenReuse.get(jwtValidator);
        assertTrue(preventTokenReuse);
    }

    @Test()
    public void testInitInvalidValue() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("RejectBeforePeriod", "some-string");
        PrivateKeyJWTClientAuthHandler privateKeyJWTClientAuthHandler = new PrivateKeyJWTClientAuthHandler();
        privateKeyJWTClientAuthHandler.init(properties);
        Field jwtValidatorField = PrivateKeyJWTClientAuthHandler.class.getDeclaredField("jwtValidator");
        jwtValidatorField.setAccessible(true);
        JWTValidator jwtValidator = (JWTValidator) jwtValidatorField.get(privateKeyJWTClientAuthHandler);
        Field field = JWTValidator.class.getDeclaredField("notAcceptBeforeTimeInMins");
        field.setAccessible(true);
        int validityPeriod = (int) field.get(jwtValidator);
        assertEquals(validityPeriod, 300);
    }

}
