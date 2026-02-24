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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.internal;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.MutualTLSClientAuthenticator;

import java.util.Dictionary;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertEquals;

/**
 * Test class for MutualTLSServiceComponent.
 */
public class MutualTLSServiceComponentTest {

    @Mock
    private BundleContext bundleContext;

    @Mock
    private ComponentContext context;

    private AutoCloseable closeable;

    @BeforeMethod
    public void setUp() {
        // Initialize mocks and keep track of the closeable to prevent memory leaks in the test suite
        closeable = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (closeable != null) {
            closeable.close();
        }
    }

    @Test
    public void testActivate() throws Exception {

        Mockito.when(context.getBundleContext()).thenReturn(bundleContext);

        final String[] serviceName = new String[1];

        // BROADER MATCHERS: Using any() for the class name and the dictionary 
        // to ensure the answer is always triggered during the OSGi registration call.
        Mockito.doAnswer(invocation -> {
            Object serviceObject = invocation.getArguments()[1];
            if (serviceObject instanceof MutualTLSClientAuthenticator) {
                serviceName[0] = serviceObject.getClass().getName();
            }
            return null;
        }).when(bundleContext).registerService(
                anyString(), 
                any(), // Use a plain any() instead of a specific class here
                any()  // Use a plain any() to catch any Dictionary/Map implementation
        );

        MutualTLSServiceComponent mutualTLSServiceComponent = new MutualTLSServiceComponent();
        mutualTLSServiceComponent.activate(context);

        // Standard TestNG assertion: actual, expected, message
        assertEquals(serviceName[0], MutualTLSClientAuthenticator.class.getName(), 
                "MutualTLSClientAuthenticator service was not registered correctly during activation.");
    }
}
