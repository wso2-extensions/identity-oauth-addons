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

import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.entitlement.EntitlementService;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * OAuthScopeValidatorDataHolderTest defines unit tests for OAuthScopeValidatorDataHolder class.
 */
public class OAuthScopeValidatorDataHolderTest {

    private OAuthScopeValidatorDataHolder authScopeValidatorDataHolder;

    @BeforeClass
    public void init() {

        authScopeValidatorDataHolder = OAuthScopeValidatorDataHolder.getInstance();
    }

    @Test
    public void testGetInstance() {

        assertNotNull(authScopeValidatorDataHolder);
        assertEquals(authScopeValidatorDataHolder, OAuthScopeValidatorDataHolder.getInstance());
    }

    @Test
    public void testGetAndSetEntitlementService() {

        // It's a good practice to ensure the state is clean before testing
        authScopeValidatorDataHolder.setEntitlementService(null);
        assertNull(authScopeValidatorDataHolder.getEntitlementService());
        
        // Mockito 5 standard mock
        EntitlementService entitlementService = Mockito.mock(EntitlementService.class);
        authScopeValidatorDataHolder.setEntitlementService(entitlementService);
        
        assertNotNull(authScopeValidatorDataHolder.getEntitlementService());
        assertEquals(authScopeValidatorDataHolder.getEntitlementService(), entitlementService);
        
        // Resetting state for other tests in the suite
        authScopeValidatorDataHolder.setEntitlementService(null);
    }
}
