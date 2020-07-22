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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.PrivilegedUserAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;


@Component(
        name = "org.wso2.carbon.identity.oauth2.clientauth.privilegeduser",
        immediate = true
)
public class PrivilegedUserAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(PrivilegedUserAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            PrivilegedUserAuthenticator privilegedUserAuthenticator = new PrivilegedUserAuthenticator();
            BundleContext bundleContext = ctxt.getBundleContext();
            bundleContext.registerService(OAuthClientAuthenticator.class.getName(), privilegedUserAuthenticator,
                    null);
            if (log.isDebugEnabled()) {
                log.debug("PrivilegedUserAuthenticator is activated");
            }
        } catch (Exception e) {
            log.fatal("Error while activating the PrivilegedUserAuthenticator. ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("PrivilegedUserAuthenticator is deactivated.");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        PrivilegedUserAuthenticatorServiceHolder.getInstance().setRealmService(realmService);
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the custom token builder bundle.");
        }
    }
    protected void unsetRealmService(RealmService realmService) {

        PrivilegedUserAuthenticatorServiceHolder.getInstance().setRealmService(null);
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the custom token builder bundle.");
        }
    }
}

