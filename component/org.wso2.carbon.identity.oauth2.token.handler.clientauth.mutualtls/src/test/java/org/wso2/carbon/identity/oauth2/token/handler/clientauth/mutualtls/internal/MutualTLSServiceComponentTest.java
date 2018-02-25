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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.MutualTLSClientAuthenticator;

import java.util.Dictionary;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;


@PrepareForTest(BundleContext.class)
public class MutualTLSServiceComponentTest {


    @Mock
    BundleContext bundleContext;

    @Mock
    private ComponentContext context;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeClass
    public void setUp() throws Exception {

        initMocks(this);
    }

    @Test
    public void testActivate() throws Exception {

        mockStatic(BundleContext.class);
        when(context.getBundleContext()).thenReturn(bundleContext);

        final String[] serviceName = new String[1];

        doAnswer(new Answer<Object>() {

            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                MutualTLSClientAuthenticator mutualTLSClientAuthenticator = (MutualTLSClientAuthenticator) invocation.getArguments()[1];
                serviceName[0] = mutualTLSClientAuthenticator.getClass().getName();
                return null;
            }
        }).when(bundleContext).registerService(anyString(), any(MutualTLSClientAuthenticator.class), any(Dictionary.class));

        MutualTLSServiceComponent mutualTLSServiceComponent = new MutualTLSServiceComponent();
        mutualTLSServiceComponent.activate(context);

        assertEquals(MutualTLSClientAuthenticator.class.getName(), serviceName[0], "error");
    }

}
