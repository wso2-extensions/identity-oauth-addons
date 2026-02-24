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

package org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.internal;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.PrivilegedUserAuthenticator;

import java.nio.file.Paths;
import java.util.Dictionary;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

public class PrivilegedUserAuthenticatorServiceComponentTest {

    private AutoCloseable closeable;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockedStatic;

    @Mock
    private BundleContext bundleContext;

    @Mock
    private ComponentContext context;

    @BeforeMethod
    public void setUp() throws Exception {
        // 1. Set carbon.home system property before Carbon classes are loaded.
        // This prevents the 'could not be initialized' error on Java 21.
        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty("carbon.home", carbonHome);

        closeable = MockitoAnnotations.openMocks(this);

        // 2. Initialize the static mock for the Carbon Context
        privilegedCarbonContextMockedStatic = Mockito.mockStatic(PrivilegedCarbonContext.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        // 3. Always close static mocks to prevent thread-leakage
        if (privilegedCarbonContextMockedStatic != null) {
            privilegedCarbonContextMockedStatic.close();
        }
        closeable.close();
    }

    @Test
    public void testActivate() throws Exception {
        // Stub the thread local context to return a mock instance
        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                .thenReturn(mockCarbonContext);

        when(context.getBundleContext()).thenReturn(bundleContext);

        final String[] serviceName = new String[1];

        // Using Mockito.doAnswer to capture the registered service
        Mockito.doAnswer(invocation -> {
            PrivilegedUserAuthenticator privilegedUserAuthenticator = 
                    (PrivilegedUserAuthenticator) invocation.getArguments()[1];
            serviceName[0] = privilegedUserAuthenticator.getClass().getName();
            return null;
        }).when(bundleContext).registerService(anyString(), any(PrivilegedUserAuthenticator.class), 
                nullable(Dictionary.class));

        PrivilegedUserAuthenticatorServiceComponent component = new PrivilegedUserAuthenticatorServiceComponent();
        component.activate(context);

        assertEquals(serviceName[0], PrivilegedUserAuthenticator.class.getName(), 
                "The Authenticator service was not registered with the correct class name.");
    }
}