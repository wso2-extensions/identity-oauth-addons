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
import org.osgi.service.component.ComponentContext;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.entitlement.EntitlementService;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

@PrepareForTest(LogFactory.class)
public class OAuthScopeValidatorServiceComponentTest {

    private OAuthScopeValidatorServiceComponent authScopeValidatorServiceComponent;
    private ComponentContext componentContext;
    private EntitlementService entitlementService;
    private OAuthScopeValidatorDataHolder authScopeValidatorDataHolder;
    private Log log = mock(Log.class);

    @BeforeClass
    public void init() {

        mockStatic(LogFactory.class);
        when(LogFactory.getLog(OAuthScopeValidatorServiceComponent.class)).thenReturn(log);
        authScopeValidatorServiceComponent = spy(new OAuthScopeValidatorServiceComponent());
        componentContext = mock(ComponentContext.class);
        entitlementService = mock(EntitlementService.class);
        authScopeValidatorDataHolder = OAuthScopeValidatorDataHolder.getInstance();
        when(log.isDebugEnabled()).thenReturn(true);
    }

    @Test
    public void testActivate() throws Exception {

        authScopeValidatorServiceComponent.activate(componentContext);
    }

    @Test
    public void testSetEntitlementService() {

        authScopeValidatorServiceComponent.setEntitlementService(entitlementService);
        assertNotNull(authScopeValidatorDataHolder.getEntitlementService());
        assertEquals(authScopeValidatorDataHolder.getEntitlementService(), entitlementService);
    }

    @Test
    public void testUnsetEntitlementService() {

        authScopeValidatorServiceComponent.unsetEntitlementService(entitlementService);
        assertNull(OAuthScopeValidatorDataHolder.getInstance().getEntitlementService());
    }
}
