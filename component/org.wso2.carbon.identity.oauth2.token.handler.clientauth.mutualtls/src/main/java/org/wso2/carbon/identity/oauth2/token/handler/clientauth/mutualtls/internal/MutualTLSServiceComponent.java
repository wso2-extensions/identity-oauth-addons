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
 * under the License
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.MutualTLSClientAuthenticator;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.introspection.ISIntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.introspection.IntrospectionResponseInterceptor;

/**
 * TLS Mutual Auth osgi Component.
 */
@Component(
        name = "org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls",
        immediate = true
)
public class MutualTLSServiceComponent {

    private static final Log log = LogFactory.getLog(MutualTLSServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            MutualTLSClientAuthenticator mutualTLSClientAuthenticator = new MutualTLSClientAuthenticator();
            IntrospectionResponseInterceptor introspectionResponseInterceptor = new IntrospectionResponseInterceptor();
            ISIntrospectionDataProvider isIntrospectionDataProvider = new ISIntrospectionDataProvider();
            bundleContext.registerService(OAuthClientAuthenticator.class.getName(), mutualTLSClientAuthenticator,
                    null);
            bundleContext.registerService(OAuthEventInterceptor.class.getName(), introspectionResponseInterceptor,
                    null);
            bundleContext.registerService(IntrospectionDataProvider.class.getName(), isIntrospectionDataProvider,
                    null);
            if (log.isDebugEnabled()) {
                log.debug("Mutual TLS bundle is activated");
            }

        } catch (Throwable e) {
            log.error("Error occurred while registering MTLS component.", e);
        }
    }
}
