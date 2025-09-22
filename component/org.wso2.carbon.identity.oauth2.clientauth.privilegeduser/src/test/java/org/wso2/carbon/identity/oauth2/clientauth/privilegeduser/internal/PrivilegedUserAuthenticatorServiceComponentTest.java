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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.PrivilegedUserAuthenticator;

import java.util.Dictionary;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;


public class PrivilegedUserAuthenticatorServiceComponentTest {

    @Mock
    BundleContext bundleContext;

    @Mock
    private ComponentContext context;

    @BeforeClass
    public void setUp() throws Exception {

        bundleContext = mock(BundleContext.class);
        context = mock(ComponentContext.class);
    }

    @Test
    public void testActivate() throws Exception {

        when(context.getBundleContext()).thenReturn(bundleContext);

        final String[] serviceName = new String[1];

        doAnswer(new Answer<Object>() {

            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                System.out.println("Service Registered: " + invocation.getArguments()[0]);
                PrivilegedUserAuthenticator privilegedUserAuthenticator =
                        (PrivilegedUserAuthenticator) invocation.getArguments()[1];
                serviceName[0] = privilegedUserAuthenticator.getClass().getName();
                return null;
            }
        }).when(bundleContext).registerService(anyString(), any(PrivilegedUserAuthenticator.class),
                nullable(Dictionary.class));

        PrivilegedUserAuthenticatorServiceComponent mutualTLSServiceComponent = new PrivilegedUserAuthenticatorServiceComponent();
        mutualTLSServiceComponent.activate(context);
        assertEquals(PrivilegedUserAuthenticator.class.getName(), serviceName[0], "error");
    }
}
