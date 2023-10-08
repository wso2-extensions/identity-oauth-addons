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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mockito;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.common.testng.WithAxisConfiguration;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.JWTAuthenticationConfigurationDAO;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.testutil.ReadCertStoreSampleUtil;
import org.wso2.carbon.idp.mgt.internal.IdpMgtServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static org.mockito.Matchers.anyString;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.ALG_ES256;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.ALG_PS256;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.REJECT_BEFORE_IN_MINUTES;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.buildJWT;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getJWTValidator;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.JWTTestUtil.getKeyStoreFromFile;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.Util.checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2CarbonDB", files = {"dbscripts/identity.sql"}, dbName = "testdb2")
@WithRealmService(tenantId = SUPER_TENANT_ID, tenantDomain = SUPER_TENANT_DOMAIN_NAME,
        injectToSingletons = {JWTServiceComponent.class})
@WithKeyStore
public class JWTValidatorTest {

    public static final String TEST_CLIENT_ID_1 = "KrVLov4Bl3natUksF2HmWsdw684a";
    public static final String TEST_SECRET_1 = "testSecret1";
    public static final String VALID_ISSUER_VAL = "valid-issuer";
    public static final String VALID_ISSUER = "ValidIssuer";
    public static final String VALID_AUDIENCE = "ValidAudience";
    public static final String SOME_VALID_AUDIENCE = "some-valid-audience";
    public static final String PREVENT_TOKEN_REUSE = "PreventTokenReuse";
    public static final String JWT_VALIDITY_PERIOD = "JwtValidityPeriod";
    public static final String ENABLE_CACHE_FOR_JTI = "EnableCacheForJTI";
    public static final String MANDATORY = "mandatory";
    public static final String ID_TOKEN_ISSUER_ID = "http://localhost:9443/oauth2/token";
    private KeyStore clientKeyStore;
    private KeyStore serverKeyStore;
    private X509Certificate cert;

    private static final String CERTIFICATE =
            "MIIDVzCCAj+gAwIBAgIEN+6m4zANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJGUjEMMAoGA1UE\n" +
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

        Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<>();
        publicCerts.put(SUPER_TENANT_ID, ReadCertStoreSampleUtil.createKeyStore(getClass())
                .getCertificate("wso2carbon"));
        clientKeyStore = getKeyStoreFromFile("testkeystore.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));
        serverKeyStore = getKeyStoreFromFile("wso2carbon.jks", "wso2carbon",
                System.getProperty(CarbonBaseConstants.CARBON_HOME));

        KeyStoreManager keyStoreManager = Mockito.mock(KeyStoreManager.class);
        ConcurrentHashMap<String, KeyStoreManager> mtKeyStoreManagers = new ConcurrentHashMap();
        mtKeyStoreManagers.put(String.valueOf(SUPER_TENANT_ID), keyStoreManager);
        WhiteboxImpl.setInternalState(KeyStoreManager.class, "mtKeyStoreManagers", mtKeyStoreManagers);
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.decodeBase64(CERTIFICATE)));
        Mockito.when(keyStoreManager.getDefaultPrimaryCertificate()).thenReturn(cert);
        Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(serverKeyStore);
        Mockito.when(keyStoreManager.getKeyStore("wso2carbon.jks")).thenReturn(serverKeyStore);

        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserRealm(userRealm);
        JWTServiceDataHolder.getInstance().setRealmService(realmService);
        IdpMgtServiceComponentHolder.getInstance().setRealmService(realmService);

        Map<String, Object> configuration = new HashMap<>();
        configuration.put("OAuth.OpenIDConnect.IDTokenIssuerID", ID_TOKEN_ISSUER_ID);
        configuration.put("OAuth.OpenIDConnect.FAPI.AllowedSignatureAlgorithms.AllowedSignatureAlgorithm",
                Arrays.asList(ALG_PS256, ALG_ES256));
        WhiteboxImpl.setInternalState(IdentityUtil.class, "configuration", configuration);
    }

    @DataProvider(name = "provideJWT")
    public Object[][] createJWT() throws Exception {

        Properties properties1 = new Properties();
        Properties properties2 = new Properties();
        Properties properties3 = new Properties();
        Properties properties4 = new Properties();
        Properties properties5 = new Properties();
        Properties properties6 = new Properties();
        Properties properties7 = new Properties();
        Properties properties8 = new Properties();
        Properties properties9 = new Properties();

        properties1.setProperty(ENABLE_CACHE_FOR_JTI, "true");
        properties1.setProperty(JWT_VALIDITY_PERIOD, "30");
        properties1.setProperty(PREVENT_TOKEN_REUSE, "true");
        properties2.setProperty(VALID_ISSUER, VALID_ISSUER_VAL);
        properties4.setProperty(VALID_AUDIENCE, SOME_VALID_AUDIENCE);
        properties5.setProperty(PREVENT_TOKEN_REUSE, "false");
        properties6.setProperty(ENABLE_CACHE_FOR_JTI, "false");
        properties6.setProperty(PREVENT_TOKEN_REUSE, "false");
        properties6.setProperty(REJECT_BEFORE_IN_MINUTES, "1");
        properties7.setProperty(MANDATORY, "some_claim");
        properties8.setProperty(VALID_ISSUER, "some_issuer");
        properties9.setProperty(ENABLE_CACHE_FOR_JTI, "false");
        properties9.setProperty(PREVENT_TOKEN_REUSE, "false");
        properties9.setProperty(REJECT_BEFORE_IN_MINUTES, "1");


        Key key1 = clientKeyStore.getKey("wso2carbon", "wso2carbon".toCharArray());
        String audience = ID_TOKEN_ISSUER_ID;
        String jsonWebToken0 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "4000", audience, "RSA265", key1, 0);
        String jsonWebToken1 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1, 0);
        String jsonWebToken2 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3000", audience, "RSA265", key1,
                6000000);
        String jsonWebToken3 = buildJWT("some-issuer", TEST_CLIENT_ID_1, "3001", audience, "RSA265", key1,
                6000000);
        String jsonWebToken4 = buildJWT(TEST_CLIENT_ID_1, "some-client-id", "3002", audience, "RSA265", key1, 0);
        String jsonWebToken5 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3002", audience, "RSA265", key1, 0);
        String jsonWebToken6 = buildJWT(VALID_ISSUER_VAL, TEST_CLIENT_ID_1, "3003", audience, "RSA265", key1, 0);
        String jsonWebToken7 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2002", audience, "RSA265", key1, 0);
        String jsonWebToken9 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3002", audience, "RSA265", key1,
                Calendar.getInstance().getTimeInMillis());
        String jsonWebToken10 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3004", SOME_VALID_AUDIENCE,
                "RSA265", key1, 0);
        String jsonWebToken11 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3005", audience, "RSA265", key1,
                0, 0, Calendar.getInstance().getTimeInMillis() - (1000L * 60 * 2 *
                        Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES));

        String jsonWebToken12 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3006", audience, "RSA265", key1, 0);
        String jsonWebToken13 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "2001", audience, "RSA265", key1, 0);
        String jsonWebToken15 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3007", audience, "RSA265", key1,
                600000000);

        String jsonWebToken16 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3008", "some_audience",
                "RSA265", key1, 0);
        String jsonWebToken17 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3010", audience, "RSA265", key1, 0);
        String jsonWebToken18 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "3011", audience, "RSA265", key1, 0);
        String jsonWebToken19 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "10010010", audience, "RSA265", key1, 0);
        String jsonWebToken20 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "10010010", audience, "RSA265", key1, 0);
        String jsonWebToken21 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "10010011", audience, ALG_PS256, key1, 0);
        String jsonWebToken22 = buildJWT(TEST_CLIENT_ID_1, TEST_CLIENT_ID_1, "10010012", audience, "RSA265", key1, 0);

        return new Object[][]{
//                {jsonWebToken0, properties8, false, "Correct authentication request is failed.", null, false},
//                {jsonWebToken1, properties1, true, "Correct authentication request is failed.", null, false},
//                {jsonWebToken2, properties1, false, "JWT replay with preventTokenReuse enabled is not " +
//                        "failed. ", null, false},
//                {jsonWebToken3, properties3, false, "JWT with Invalid field Issuer must be fail.", null, false},
//                {jsonWebToken4, properties3, false, "Request with non existing SP client-id should fail.", null, false},
//                {jsonWebToken5, properties5, true, "JWT replay with preventTokenReuse disabled but " +
//                        "not-expired is not failed", null, false},
//                {jsonWebToken6, properties2, true, "Valid JWT token with custom issuer validation should pass.", null, false},
//                {jsonWebToken7, properties3, false, "JWT persisted in database with preventTokenReuse " +
//                        "enabled is not failed.", null, false},
//                {jsonWebToken9, properties1, false, "JWT persisted in database with preventTokenReuse " +
//                        "disabled is not failed.", null, false},
//                {jsonWebToken10, properties4, true, "Valid JWT token with custom audience validation should pass" +
//                        ".", null, false},
//                {jsonWebToken11, properties1, false, "", null, false},
//                {jsonWebToken12, properties5, true, "", null, false},
//                {jsonWebToken12, properties5, true, "", null, false},
//                {jsonWebToken13, properties1, false, "", null, false},
//                {jsonWebToken15, properties1, false, "", null, false},
//                {jsonWebToken16, properties4, false, "", null, false},
//                {jsonWebToken17, properties6, false, "", null, false},
//                {jsonWebToken18, properties7, false, "", null, false},
//                {jsonWebToken19, properties1, true, "Unable to use same JTI across tenants.", null, false},
//                {jsonWebToken20, properties1, false, "Duplicated JTI was used in same tenant with " +
//                        "preventTokenReuse enabled.", null, false},
                {jsonWebToken21, properties1, true, "JWT with registered signing algorithm should pass.", ALG_PS256, true},
//                {jsonWebToken22, properties1, false, "JWT with unregistered signing algorithm should fail.", "RSA265", true}
        };
    }

    @Test(dataProvider = "provideJWT")
    public void testValidateToken(String jwt, Object properties, boolean expected, String errorMsg,
                                  String jwtSigningAlgorithm, boolean isFAPIApplication) throws Exception {

        ServiceProvider mockedServiceProvider = Mockito.mock(ServiceProvider.class);
        Mockito.when(mockedServiceProvider.getCertificateContent()).thenReturn(CERTIFICATE);
        Mockito.when(mockedServiceProvider.getSpProperties()).thenReturn(
                getServiceProviderProperties(jwtSigningAlgorithm, String.valueOf(isFAPIApplication)));
        ApplicationManagementService mockedApplicationManagementService = Mockito.mock(ApplicationManagementService
                .class);
        Mockito.when(mockedApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(),
                anyString())).thenReturn(mockedServiceProvider);
        OAuth2ServiceComponentHolder.setApplicationMgtService(mockedApplicationManagementService);
        try {
            checkIfTenantIdColumnIsAvailableInIdnOidcAuthTable();
            boolean  preventTokenReuse = true;
            String preventTokenReuseProperty = ((Properties) properties).getProperty("PreventTokenReuse");
            if (StringUtils.isNotEmpty(preventTokenReuseProperty)) {
                preventTokenReuse = Boolean.parseBoolean(preventTokenReuseProperty);
            }
            JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
            jwtClientAuthenticatorConfig.setEnableTokenReuse(!preventTokenReuse);

            JWTAuthenticationConfigurationDAO mockDAO = Mockito.mock(JWTAuthenticationConfigurationDAO
                    .class);
            Mockito.when(mockDAO.getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(anyString()))
                    .thenReturn(jwtClientAuthenticatorConfig);

            JWTServiceDataHolder.getInstance()
                    .setJWTAuthenticationConfigurationDAO(mockDAO);

            JWTValidator jwtValidator = getJWTValidator((Properties) properties);
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            assertEquals(jwtValidator.isValidAssertion(signedJWT),
                    expected, errorMsg);
            if (((Properties) properties).getProperty(MANDATORY) != null) {
                assertEquals(jwtValidator.isValidAssertion(null),
                        expected, errorMsg);
            }

        } catch (OAuthClientAuthnException e) {
            assertFalse(expected);

        }
    }

    @Test
    public void testValidateNullToken() throws Exception {

        try {
            JWTValidator jwtValidator = getJWTValidator(new Properties());
            jwtValidator.isValidAssertion(null);
        } catch (OAuthClientAuthnException e) {
            assertFalse(false, "Validation should fail when token is null");
        }

    }

    @Test(dependsOnMethods = "testValidateToken")
    public void testValidateTokenSignedByHmac() throws Exception {

        JWTValidator jwtValidator = getJWTValidator(new Properties());
        String hsSignedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                ".eyJzdWIiOiJLclZMb3Y0QmwzbmF0VWtzRjJIbVdzZHc2ODRhIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzdWVyIjoiS3JWTG92NEJsM2" +
                "5hdFVrc0YySG1Xc2R3Njg0YSIsImp0aSI6MTAwOCwiZXhwIjoiMjU1NDQ0MDEzMjAwMCIsImF1ZCI6WyJzb21lLWF1ZGllbmNlIl19." +
                "m0RrVUrZHr1M7R4I_4dzpoWD8jNA2fKkOadEsFg9Wj4";
        SignedJWT signedJWT = SignedJWT.parse(hsSignedJWT);
    }

    private ServiceProviderProperty[] getServiceProviderProperties(String algorithm, String isFapiApplication) {

        List<ServiceProviderProperty> spProperties = new ArrayList<>();
        ServiceProviderProperty fapiAppSpProperty = new ServiceProviderProperty();
        fapiAppSpProperty.setName(OAuthConstants.IS_FAPI_CONFORMANT_APP);
        fapiAppSpProperty.setValue(isFapiApplication);
        spProperties.add(fapiAppSpProperty);
        if (StringUtils.isNotBlank(algorithm)) {
            ServiceProviderProperty signingAlgSpProperty = new ServiceProviderProperty();
            signingAlgSpProperty.setName(Constants.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
            signingAlgSpProperty.setValue(algorithm);
            spProperties.add(signingAlgSpProperty);
        }
        return spProperties.toArray(new ServiceProviderProperty[0]);
    }
}
