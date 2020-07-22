/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 */

package org.wso2.carbon.identity.oauth2.clientauth.privilegeduser;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.transport.http.HTTPConstants;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.internal.PrivilegedUserAuthenticatorServiceHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({
        HttpServletRequest.class,
        OAuth2Util.class,
        IdentityTenantUtil.class,
        PrivilegedUserAuthenticatorServiceHolder.class,
        UserCoreUtil.class,
})
@WithCarbonHome
public class PrivilegedUserAuthenticatorTest extends PowerMockIdentityBaseTest {

    private PrivilegedUserAuthenticator privilegedUserAuthenticator = new PrivilegedUserAuthenticator();
    private static final String CREDENTIALS = "credentials";
    private static final String FAULT_CREDENTIALS_PARAM = "faultcredentials";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String CLIENT_ID = "KrVLov4Bl3natUksF2HmWsdw684a";
    private static final String REVOKE_ENDPOINT = "/oauth2/revoke";

    @Mock
    private RealmService realmService;
    @Mock
    private UserRealm userRealm;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private PrivilegedUserAuthenticatorServiceHolder privilegedUserAuthenticatorServiceHolder;
    @Mock
    private RealmConfiguration mockedRealmConfiguration;
    @Mock
    private AuthorizationManager authorizationManager;

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                // Correct request parameter name with valid username and password.
                {CREDENTIALS, getBase64EncodedUserAuthHeader(USERNAME,
                        PASSWORD), new HashMap<String, List>(), true},

                // Fault  request parameter name with valid username and password.
                {FAULT_CREDENTIALS_PARAM, getBase64EncodedUserAuthHeader(USERNAME,
                        PASSWORD), new HashMap<String, List>(), false},

                // No credential parameter
                { null, null, new HashMap<String, List>(), false},


        };
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(String paramName, String paramValue, HashMap<String, List> bodyContent, boolean
            canHandle) throws Exception {

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        List<String> userCredentialContent = new ArrayList<>();
        userCredentialContent.add(paramName);
        bodyContent.put(paramName, userCredentialContent);
        when(httpServletRequest.getRequestURI()).thenReturn(REVOKE_ENDPOINT);
        PowerMockito.when(httpServletRequest.getHeader(paramName)).thenReturn(paramValue);
        assertEquals(privilegedUserAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @Test
    public void testGetName() throws Exception {

        assertEquals("PrivilegedUserAuthenticator", privilegedUserAuthenticator.getName(),
                "PrivilegedUserAuthenticator name has changed.");
    }

    @Test
    public void testGetClientId() throws Exception {

        Map<String, List> bodyContent = new HashMap<>();
        List<String> clientIDContent = new ArrayList<>();
        clientIDContent.add(CLIENT_ID);
        bodyContent.put("client_id", clientIDContent);
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        String clientId = privilegedUserAuthenticator.getClientId(httpServletRequest, bodyContent,
                new OAuthClientAuthnContext());
        assertEquals(clientId, "KrVLov4Bl3natUksF2HmWsdw684a", "The expected client id is not found.");
    }


    @DataProvider(name = "testClientAuthnData")
    public Object[][] testClientAuthnData() {

        return new Object[][]{

                // Correct authorization header present with correct encoding
                {HTTPConstants.HEADER_AUTHORIZATION, getBase64EncodedUserAuthHeader(USERNAME,
                        PASSWORD), new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID),
                        true},
        };
    }

    @Test(dataProvider = "testClientAuthnData")
    public void testAuthenticateClient(String headerName, String headerValue, HashMap<String, List> bodyContent,
                                       Object oAuthClientAuthnContextObj,
                                       boolean authenticationResult) throws Exception {

        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(-1234);

        mockStatic(PrivilegedUserAuthenticatorServiceHolder.class);
        when(PrivilegedUserAuthenticatorServiceHolder.getInstance()).thenReturn(privilegedUserAuthenticatorServiceHolder);

        mockStatic(UserCoreUtil.class);

        List<String> userCredentialContent = new ArrayList<>();
        userCredentialContent.add(getBase64EncodedUserAuthHeader(USERNAME, PASSWORD));
        bodyContent.put(CREDENTIALS, userCredentialContent);

        when(privilegedUserAuthenticatorServiceHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.authenticate(anyString(), any())).thenReturn(true);

        when(userRealm.getRealmConfiguration()).thenReturn(mockedRealmConfiguration);
        when(UserCoreUtil.getDomainName(mockedRealmConfiguration)).thenReturn("PRIMARY");

        when(userRealm.getAuthorizationManager()).thenReturn(authorizationManager);
        when(authorizationManager.isUserAuthorized(anyString(), anyString(), anyString())).thenReturn(true);

        PowerMockito.when(httpServletRequest.getHeader(headerName)).thenReturn(headerValue);
        assertEquals(privilegedUserAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                oAuthClientAuthnContext), authenticationResult, "Expected client authentication result was not " +
                "received");
    }

    private  String getBase64EncodedUserAuthHeader(String userName, String password) {

        return "User " + Base64Utils.encode((userName + ":" + password).getBytes());
    }

    private OAuthClientAuthnContext buildOAuthClientAuthnContext(String clientId) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        return oAuthClientAuthnContext;
    }
}
