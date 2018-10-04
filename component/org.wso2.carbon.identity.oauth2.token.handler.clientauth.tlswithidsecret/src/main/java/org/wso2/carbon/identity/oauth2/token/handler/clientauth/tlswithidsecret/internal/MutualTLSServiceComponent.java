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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret.MutualTLSWithIdSecretAuthenticator;

/**
 * TLS Mutual Auth with basic osgi Component.
 */
@Component(
        name = "org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret",
        immediate = true
)
public class MutualTLSServiceComponent {

    private static Log log = LogFactory.getLog(MutualTLSServiceComponent.class);
    private BundleContext bundleContext;

    @Activate
    protected void activate(ComponentContext context) {

        try {
            // Registering MutualTLSClientAuthenticator as an OSGIService.
            bundleContext = context.getBundleContext();
            MutualTLSWithIdSecretAuthenticator mutualTLSWithIdSecretAuthenticator = new MutualTLSWithIdSecretAuthenticator();
            bundleContext.registerService(OAuthClientAuthenticator.class.getName(), mutualTLSWithIdSecretAuthenticator,
                    null);
            if (log.isDebugEnabled()) {
                log.debug("Mutual TLS with basic auth bundle is activated");
            }

        } catch (Throwable e) {
            log.error("Error occurred while registering MutualTLSWithIdSecretAuthenticator.", e);
        }
    }
}
