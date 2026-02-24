/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.validators;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.EntitlementService;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.xacml.XACMLScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.xacml.constants.XACMLScopeValidatorConstants;
import org.wso2.carbon.identity.oauth2.validators.xacml.internal.OAuthScopeValidatorDataHolder;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
public class XACMLScopeValidatorTest extends IdentityBaseTest {

    private static final String ADMIN_USER = "admin_user";
    private static final String APP_NAME = "SP_APP";
    private static final String DECISION = "decision";
    private static final String RULE_EFFECT_PERMIT = "Permit";
    private static final String RULE_EFFECT_NOT_APPLICABLE = "NotApplicable";
    private static final String POLICY = "policy";
    private static final String ERROR = "error";
    private static final String CONSUMER_KEY = "consumer-key";

    private final XACMLScopeValidator xacmlScopeValidator = new XACMLScopeValidator();
    private AccessTokenDO accessTokenDO;
    private OAuthAppDO authApp;
    private final String RESOURCE = "resource";
    private final String accessToken = "cf7da41d-6a73-3cfe-9c17-9cf1927c7f46";
    private OAuthTokenReqMessageContext tokenReqMessageContext;
    private OAuthAuthzReqMessageContext oauthAuthzMsgCtx;
    private AuthenticatedUser authenticatedUser;
    private AuthorizationGrantCacheEntry authorizationGrantCacheEntry;

    private MockedStatic<FrameworkUtils> frameworkUtilsMock;
    private MockedStatic<PolicyCreatorUtil> policyCreatorUtilMock;
    private MockedStatic<PolicyBuilder> policyBuilderMock;
    private MockedStatic<OAuth2Util> oAuth2UtilMock;
    private MockedStatic<AuthorizationGrantCache> authGrantCacheMock;
    private MockedStatic<IdentityConfigParser> identityConfigParserMock;
    private MockedStatic<OAuthServerConfiguration> oauthServerConfigMock;

    @BeforeClass
    public void setUpSuite() throws Exception {
        resetSingleton(IdentityConfigParser.class);
        resetSingleton(OAuthServerConfiguration.class);

        identityConfigParserMock = Mockito.mockStatic(IdentityConfigParser.class);
        identityConfigParserMock.when(IdentityConfigParser::getInstance).thenReturn(mock(IdentityConfigParser.class));

        oauthServerConfigMock = Mockito.mockStatic(OAuthServerConfiguration.class);
        oauthServerConfigMock.when(OAuthServerConfiguration::getInstance).thenReturn(mock(OAuthServerConfiguration.class));

        initVariables();
    }

    private void initVariables() {
        String[] scopeArray = new String[]{"scope1", "scope2", "scope3"};
        authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(ADMIN_USER);
        
        accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(CONSUMER_KEY);
        accessTokenDO.setAuthzUser(authenticatedUser);
        accessTokenDO.setScope(scopeArray);
        accessTokenDO.setAccessToken(accessToken);
        
        authApp = new OAuthAppDO();
        authApp.setApplicationName(APP_NAME);

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);

        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oauth2AccessTokenReqDTO.setClientId(CONSUMER_KEY);
        oauth2AccessTokenReqDTO.setScope(scopeArray);
        tokenReqMessageContext = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUser);

        OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO = new OAuth2AuthorizeReqDTO();
        oAuth2AuthorizeReqDTO.setConsumerKey(CONSUMER_KEY);
        oAuth2AuthorizeReqDTO.setUser(authenticatedUser);
        oAuth2AuthorizeReqDTO.setScopes(scopeArray);
        oauthAuthzMsgCtx = new OAuthAuthzReqMessageContext(oAuth2AuthorizeReqDTO);
    }

    @BeforeMethod
    public void setUpMocks() {
        frameworkUtilsMock = Mockito.mockStatic(FrameworkUtils.class);
        policyCreatorUtilMock = Mockito.mockStatic(PolicyCreatorUtil.class);
        policyBuilderMock = Mockito.mockStatic(PolicyBuilder.class);
        oAuth2UtilMock = Mockito.mockStatic(OAuth2Util.class);
        authGrantCacheMock = Mockito.mockStatic(AuthorizationGrantCache.class);
    }

    @AfterMethod
    public void tearDownMocks() {
        frameworkUtilsMock.close();
        policyCreatorUtilMock.close();
        policyBuilderMock.close();
        oAuth2UtilMock.close();
        authGrantCacheMock.close();
        OAuthScopeValidatorDataHolder.getInstance().setEntitlementService(null);
    }

    @AfterClass
    public void tearDownSuite() {
        identityConfigParserMock.close();
        oauthServerConfigMock.close();
    }

    @DataProvider(name = "createRequestObj")
    public Object[][] createRequestObj() {
        return new Object[][]{
                {accessTokenDO.getScope(), XACMLScopeValidatorConstants.ACTION_VALIDATE, RESOURCE, accessTokenDO.getAccessToken()},
                {tokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope(), XACMLScopeValidatorConstants.ACTION_SCOPE_VALIDATE, null, null},
                {oauthAuthzMsgCtx.getAuthorizationReqDTO().getScopes(), XACMLScopeValidatorConstants.ACTION_SCOPE_VALIDATE, null, null},
        };
    }

    @Test(dataProvider = "createRequestObj")
    public void testCreateRequestObj(String[] scopes, String action, String resource, String token) throws Exception {
        // Stub PolicyCreatorUtil to return a valid DO/DTO, otherwise createRequest returns null
        RequestElementDTO mockElementDTO = mock(RequestElementDTO.class);
        policyCreatorUtilMock.when(() -> PolicyCreatorUtil.createRequestElementDTO(any(RequestDTO.class)))
                .thenReturn(mockElementDTO);

        // Setup PolicyBuilder mock
        PolicyBuilder policyBuilder = mock(PolicyBuilder.class);
        policyBuilderMock.when(PolicyBuilder::getInstance).thenReturn(policyBuilder);
        policyBuilderMock.when(() -> policyBuilder.buildRequest(any(RequestElementDTO.class))).thenReturn(POLICY);
        
        mockAuthorizationGrantCache();

        Method method = XACMLScopeValidator.class.getDeclaredMethod("createRequest", 
                String[].class, AuthenticatedUser.class, OAuthAppDO.class, String.class, String.class, String.class);
        method.setAccessible(true);
        String request = (String) method.invoke(xacmlScopeValidator, scopes, authenticatedUser, authApp, action, resource, token);
        
        assertNotNull(request, "Generated XACML request should not be null.");
        assertEquals(request, POLICY);
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidatedScope() throws Exception {
        setupCommonEntitlementMocks();
        EntitlementService entitlementService = OAuthScopeValidatorDataHolder.getInstance().getEntitlementService();

        Mockito.when(entitlementService.getDecision(anyString())).thenReturn(createXacmlResponse(DECISION));
        assertFalse(xacmlScopeValidator.validateScope(accessTokenDO, RESOURCE));

        Mockito.when(entitlementService.getDecision(anyString())).thenReturn(createXacmlResponse(RULE_EFFECT_PERMIT));
        assertTrue(xacmlScopeValidator.validateScope(accessTokenDO, RESOURCE));

        Mockito.when(entitlementService.getDecision(anyString())).thenThrow(new EntitlementException(ERROR));
        xacmlScopeValidator.validateScope(accessTokenDO, RESOURCE);
    }

    private void setupCommonEntitlementMocks() throws Exception {
        oAuth2UtilMock.when(() -> OAuth2Util.getAppInformationByClientId(anyString())).thenReturn(authApp);
        
        RequestElementDTO requestElementDTO = mock(RequestElementDTO.class);
        policyCreatorUtilMock.when(() -> PolicyCreatorUtil.createRequestElementDTO(any(RequestDTO.class))).thenReturn(requestElementDTO);
        
        PolicyBuilder policyBuilder = mock(PolicyBuilder.class);
        policyBuilderMock.when(PolicyBuilder::getInstance).thenReturn(policyBuilder);
        policyBuilderMock.when(() -> policyBuilder.buildRequest(any(RequestElementDTO.class))).thenReturn(POLICY);
        
        EntitlementService entitlementService = mock(EntitlementService.class);
        OAuthScopeValidatorDataHolder.getInstance().setEntitlementService(entitlementService);
        
        mockAuthorizationGrantCache();
    }

    private void mockAuthorizationGrantCache() {
        AuthorizationGrantCache authorizationGrantCache = mock(AuthorizationGrantCache.class);
        authGrantCacheMock.when(AuthorizationGrantCache::getInstance).thenReturn(authorizationGrantCache);
        Mockito.when(authorizationGrantCache.getValueFromCacheByToken(any(AuthorizationGrantCacheKey.class)))
                .thenReturn(authorizationGrantCacheEntry);
    }

    private String createXacmlResponse(String decision) {
        return "<ns:root xmlns:ns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\">"
                + "<ns:Result><ns:Decision>" + decision + "</ns:Decision></ns:Result></ns:root>";
    }

    private void resetSingleton(Class<?> clazz) throws Exception {
        Field instanceField;
        try {
            instanceField = clazz.getDeclaredField("instance");
        } catch (NoSuchFieldException e) {
            instanceField = clazz.getDeclaredField("parser");
        }
        instanceField.setAccessible(true);
        instanceField.set(null, null);
    }
}