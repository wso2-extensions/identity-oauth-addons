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

package org.wso2.carbon.identity.oauth2.validators.xacml.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.entitlement.EntitlementService;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit tests for OAuthScopeValidatorServiceComponent using Mockito 5.
 */
public class OAuthScopeValidatorServiceComponentTest {

    private OAuthScopeValidatorServiceComponent authScopeValidatorServiceComponent;
    private ComponentContext componentContext;
    private EntitlementService entitlementService;
    private OAuthScopeValidatorDataHolder authScopeValidatorDataHolder;
    private Log log;
    private MockedStatic<LogFactory> logFactoryMockedStatic;

    @BeforeMethod
    public void setUp() {

        log = mock(Log.class);
        // Mockito 5 Static Mocking for LogFactory
        logFactoryMockedStatic = Mockito.mockStatic(LogFactory.class);
        logFactoryMockedStatic.when(() -> LogFactory.getLog(OAuthScopeValidatorServiceComponent.class)).thenReturn(log);
        
        authScopeValidatorServiceComponent = spy(new OAuthScopeValidatorServiceComponent());
        componentContext = mock(ComponentContext.class);
        entitlementService = mock(EntitlementService.class);
        authScopeValidatorDataHolder = OAuthScopeValidatorDataHolder.getInstance();
        
        when(log.isDebugEnabled()).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() {

        // It's critical to close MockedStatic to avoid thread leakage
        logFactoryMockedStatic.close();
        // Clean up the singleton to ensure isolation between test runs
        authScopeValidatorDataHolder.setEntitlementService(null);
    }

    @Test
    public void testActivate() throws Exception {

        authScopeValidatorServiceComponent.activate(componentContext);
        // Verify that activation happened without exceptions
    }

    @Test
    public void testSetEntitlementService() {

        authScopeValidatorServiceComponent.setEntitlementService(entitlementService);
        assertNotNull(authScopeValidatorDataHolder.getEntitlementService());
        assertEquals(authScopeValidatorDataHolder.getEntitlementService(), entitlementService);
    }

    @Test
    public void testUnsetEntitlementService() {

        // First set it so we can test the unsetting
        authScopeValidatorDataHolder.setEntitlementService(entitlementService);
        authScopeValidatorServiceComponent.unsetEntitlementService(entitlementService);
        assertNull(OAuthScopeValidatorDataHolder.getInstance().getEntitlementService());
    }
}