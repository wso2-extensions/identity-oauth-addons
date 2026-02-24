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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.internal.PrivilegedUserAuthenticatorServiceHolder;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
public class PrivilegedUserAuthenticatorTest {

    private final PrivilegedUserAuthenticator privilegedUserAuthenticator = new PrivilegedUserAuthenticator();
    private AutoCloseable closeable;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockedStatic;

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

    @BeforeMethod
    public void setUp() {
        // Fix for Java 21: Prevents PrivilegedCarbonContext from crashing on load
        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty("carbon.home", carbonHome);
        
        closeable = MockitoAnnotations.openMocks(this);
        
        // Initialize the static mock here
        privilegedCarbonContextMockedStatic = Mockito.mockStatic(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(mock(PrivilegedCarbonContext.class));
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (privilegedCarbonContextMockedStatic != null) {
            privilegedCarbonContextMockedStatic.close();
            privilegedCarbonContextMockedStatic = null;
        }
        if (closeable != null) {
            closeable.close();
        }
    }

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {
        return new Object[][]{
                {"username", "password", new HashMap<String, List>(), true},
                {"user", "password", new HashMap<String, List>(), false},
                {"username", "pass", new HashMap<String, List>(), false},
                {"user", "pass", new HashMap<String, List>(), false},
                {null, null, new HashMap<String, List>(), false},
        };
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(String userNameParam, String passwordParam,
                                    Map<String, List> bodyContent, boolean canHandle) throws Exception {

        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        List<String> userNameCredentials = new ArrayList<>();
        userNameCredentials.add("user1");
        List<String> passwordCredentials = new ArrayList<>();
        passwordCredentials.add("pass1");
        
        if (userNameParam != null) bodyContent.put(userNameParam, userNameCredentials);
        if (passwordParam != null) bodyContent.put(passwordParam, passwordCredentials);
        
        Mockito.when(httpServletRequest.getRequestURI()).thenReturn("/oauth2/revoke");
        
        assertEquals(privilegedUserAuthenticator.canAuthenticate(httpServletRequest, bodyContent, 
                new OAuthClientAuthnContext()), canHandle);
    }

    @Test
    public void testGetName() {
        assertEquals("PrivilegedUserAuthenticator", privilegedUserAuthenticator.getName());
    }

    @Test
    public void testAuthenticateClient() throws Exception {
        OAuthClientAuthnContext contextObj = new OAuthClientAuthnContext();
        contextObj.setClientId("test-client");
        HttpServletRequest request = mock(HttpServletRequest.class);

        try (MockedStatic<IdentityTenantUtil> tenantUtilMock = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<PrivilegedUserAuthenticatorServiceHolder> holderMock = Mockito.mockStatic(PrivilegedUserAuthenticatorServiceHolder.class);
             MockedStatic<UserCoreUtil> userUtilMock = Mockito.mockStatic(UserCoreUtil.class)) {

            tenantUtilMock.when(() -> IdentityTenantUtil.getTenantIdOfUser(anyString())).thenReturn(-1234);
            holderMock.when(PrivilegedUserAuthenticatorServiceHolder::getInstance).thenReturn(privilegedUserAuthenticatorServiceHolder);

            Mockito.when(privilegedUserAuthenticatorServiceHolder.getRealmService()).thenReturn(realmService);
            Mockito.when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
            Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
            
            Mockito.when(userStoreManager.authenticate(anyString(), any())).thenReturn(true);
            Mockito.when(userRealm.getRealmConfiguration()).thenReturn(mockedRealmConfiguration);
            Mockito.when(userRealm.getAuthorizationManager()).thenReturn(authorizationManager);
            Mockito.when(authorizationManager.isUserAuthorized(anyString(), anyString(), anyString())).thenReturn(true);

            userUtilMock.when(() -> UserCoreUtil.getDomainName(any(RealmConfiguration.class))).thenReturn("PRIMARY");
            userUtilMock.when(() -> UserCoreUtil.addDomainToName(anyString(), anyString())).thenCallRealMethod();

            // Using raw List in the Map to satisfy the method signature and generic constraints
            Map<String, List> bodyContent = new HashMap<>();
            List<String> userList = new ArrayList<>(); userList.add("user1");
            List<String> passList = new ArrayList<>(); passList.add("pass1");
            bodyContent.put("username", userList);
            bodyContent.put("password", passList);

            // Reflection to call authenticateClient without importing the WSO2 Exception class
            // Map.class must be used here to match the interface-based signature
            Method method = PrivilegedUserAuthenticator.class.getMethod("authenticateClient", 
                    HttpServletRequest.class, Map.class, OAuthClientAuthnContext.class);
            
            Boolean result = (Boolean) method.invoke(privilegedUserAuthenticator, request, bodyContent, contextObj);
            assertTrue(result);
        }
    }
}