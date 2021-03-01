package org.wso2.carbon.identity.dpop.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;

@Component(
        name = "org.wso2.carbon.identity.oauth.dpop.internal.DPoPServiceComponent",
        immediate = true
)
public class DPoPServiceComponent {
    private static final Log log = LogFactory.getLog(DPoPServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context){
        context.getBundleContext().registerService(OAuthEventInterceptor.class, new OauthDPoPInterceptorHandlerProxy(),null);
        if (log.isDebugEnabled()){
            log.debug("DPoP Interceptor is Activated");
        }
    }

    @Deactivate
    protected void deActivate(ComponentContext context){

    }
}
