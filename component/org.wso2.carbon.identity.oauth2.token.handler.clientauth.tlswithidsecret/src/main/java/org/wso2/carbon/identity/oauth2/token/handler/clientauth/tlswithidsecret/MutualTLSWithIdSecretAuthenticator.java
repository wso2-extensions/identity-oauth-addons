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
package org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.BasicAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret.util.MutualTLSUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret.util.MutualTLSUtil.JAVAX_SERVLET_REQUEST_CERTIFICATE;

/**
 * This class is an enhancement for BasicAuthClientAuthenticator which validates the client certificate
 * in addition to the client id and secret authentication
 *
 */
public class MutualTLSWithIdSecretAuthenticator extends BasicAuthClientAuthenticator {

    private static Log log = LogFactory.getLog(MutualTLSWithIdSecretAuthenticator.class);

    public boolean authenticateClient(HttpServletRequest request, Map<String, List> bodyParams,
                                      OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {

        if (!super.authenticateClient(request, bodyParams, oAuthClientAuthnContext)) {
            return false;
        }

        if (StringUtils.isEmpty(oAuthClientAuthnContext.getClientId())) {
            oAuthClientAuthnContext.setClientId(this.getClientId(request, bodyParams, oAuthClientAuthnContext));
        }

        try {

            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthClientAuthnContext.getClientId());
            X509Certificate registeredCert = null;
            try {
                registeredCert = (X509Certificate) OAuth2Util
                        .getX509CertOfOAuthApp(oAuthClientAuthnContext.getClientId(), tenantDomain);
            } catch (IdentityOAuth2Exception e) {
                if (e.getCause() instanceof CertificateException) {
                    throw e;
                } else {
                    // This means certificate is not configured in service provider. In that case basic authentication
                    // would be performed
                    return super.authenticateClient(request, bodyParams, oAuthClientAuthnContext);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Authenticating client : " + oAuthClientAuthnContext.getClientId() + " with public " +
                        "certificate.");
            }

            X509Certificate requestCert;
            Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
            if (certObject instanceof X509Certificate[]) {
                X509Certificate[] cert = (X509Certificate[]) certObject;
                requestCert = cert[0];
            } else if (certObject instanceof X509Certificate){
                requestCert = (X509Certificate) certObject;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Could not find client certificate in required format for client: " +
                            oAuthClientAuthnContext.getClientId());
                }
                return false;
            }

            return authenticate(registeredCert, requestCert);

        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.SERVER_ERROR, "Error occurred while retrieving " +
                    "public certificate of client ID: " + oAuthClientAuthnContext.getClientId(), e);
        } catch (InvalidOAuthClientException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_CLIENT, "Error occurred while retrieving " +
                    "tenant domain for the client ID: " + oAuthClientAuthnContext.getClientId(), e);
        } catch (Exception e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Unexpected error while authenticating client: " + oAuthClientAuthnContext.getClientId(), e);
        }

    }

    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> bodyParams,
                                   OAuthClientAuthnContext oAuthClientAuthnContext) {

        // This authenticator will be skipped if BasicAuthClientAuthenticator was engaged
        return !oAuthClientAuthnContext.getExecutedAuthenticators().contains(super.getName()) &&
                super.canAuthenticate(request, bodyParams, oAuthClientAuthnContext);

    }

    public String getName() {
        return "MutualTLSWithIdSecretAuthenticator";
    }

    /**
     * Returns the execution order of this authenticator
     *
     * @return Execution place within the order
     */
    @Override
    public int getPriority() {

        return 101;
    }

    /**
     * Authenticate the client by comparing the public key of the registered public certificate against the public
     * key of the certificate presented at TLS hand shake for authentication.
     *
     * @param registeredCert X.509 certificate registered at service provider configuration.
     * @param requestCert    X.509 certificate presented to server during TLS hand shake.
     * @return Whether the client was successfully authenticated or not.
     */
    protected boolean authenticate(X509Certificate registeredCert, X509Certificate requestCert)
            throws OAuthClientAuthnException {

        boolean trustedCert = false;
        try {
            String publicKeyOfRegisteredCert = MutualTLSUtil.getThumbPrint(registeredCert);
            String publicKeyOfRequestCert = MutualTLSUtil.getThumbPrint(requestCert);
            if (StringUtils.equals(publicKeyOfRegisteredCert, publicKeyOfRequestCert)) {
                if (log.isDebugEnabled()) {
                    log.debug("Client certificate thumbprint matched with the registered certificate thumbprint.");
                }
                trustedCert = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Client Authentication failed. Client certificate thumbprint did not match with the " +
                            "registered certificate thumbprint.");
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_GRANT, "Error occurred while " +
                    "generating certificate thumbprint. Error: " + e.getMessage(), e);
        } catch (CertificateEncodingException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_GRANT, "Error occurred while " +
                    "generating certificate thumbprint. Error: " + e.getMessage(), e);
        }
        return trustedCert;
    }

    /**
     * Check for the existence of a valid certificate in required format in the request attribute map.
     *
     * @param request HttpServletRequest which is the incoming request.
     * @return Whether a certificate exists or not.
     */
    private boolean validCertExistsAsAttribute(HttpServletRequest request) {

        Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
        return (certObject instanceof X509Certificate[] || certObject instanceof X509Certificate);
    }
}
