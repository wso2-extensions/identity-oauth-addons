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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.handlers;


import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.ClientCredentialsGrantHandler;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * This class is used to bound the MTLS certificate of the client to the access token issued. Here, the certificate is
 * bounded to the access token using a hidden scope.
 *
 * @see <href="https://tools.ietf.org/html/draft-ietf-oauth-mtls-17">IETF OAuth MTLS</>
 */
public class MTLSTokenBindingClientCredentialsGrantHandler extends ClientCredentialsGrantHandler {

    private static Log log = LogFactory.getLog(MTLSTokenBindingClientCredentialsGrantHandler.class);

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO = super.issue(tokReqMsgCtx);
        tokReqMsgCtx.setScope(getReducedResponseScopes(tokReqMsgCtx.getScope()));
        return oAuth2AccessTokenRespDTO;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        boolean validateScope = super.validateScope(tokReqMsgCtx);

        // Get MTLS certificate from transport headers.
        HttpRequestHeader[] requestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        String headerName = IdentityUtil.getProperty(MutualTLSUtil.MTLS_AUTH_HEADER);

        Optional<HttpRequestHeader> certHeader =
                Arrays.stream(requestHeaders).filter(h -> headerName.equals(h.getName())).findFirst();

        String authenticatorType = (String) tokReqMsgCtx.getOauth2AccessTokenReqDTO().getoAuthClientAuthnContext()
                .getParameter(MutualTLSUtil.AUTHENTICATOR_TYPE_PARAM);
        if (certHeader.isPresent() && MutualTLSUtil.AUTHENTICATOR_TYPE_MTLS.equals(authenticatorType)) {
            Base64URL certThumbprint = null;
            if (log.isDebugEnabled()) {
                log.debug("Client MTLS certificate found: " + certHeader);
            }
            try {
                X509Certificate certificate = parseCertificate(certHeader.get().getValue()[0]);
                certThumbprint = X509CertUtils.computeSHA256Thumbprint(certificate);
            } catch (CertificateException e) {
                log.error("Error occurred while calculating the thumbprint of the client MTLS certificate", e);
                return false;
            }

            // Add certificate thumbprint as a hidden scope of the token.
            if (certThumbprint != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Client MTLS certificate thumbprint: " + certThumbprint);
                }
                String[] scopes = tokReqMsgCtx.getScope();
                List<String> scopesList = new LinkedList<>(Arrays.asList(scopes));
                scopesList.add(MutualTLSUtil.CERT_THUMBPRINT + "#" + MutualTLSUtil.SHA256_DIGEST_ALGORITHM +
                        MutualTLSUtil.CERT_THUMBPRINT_SEPARATOR + certThumbprint.toString());
                tokReqMsgCtx.setScope(scopesList.toArray(new String[scopesList.size()]));
            }
        }

        return validateScope;
    }

    /**
     * Return Certificate for give Certificate Content.
     *
     * @param content Certificate Content.
     * @return X509Certificate.
     * @throws CertificateException Certificate Exception.
     */
    private static X509Certificate parseCertificate(String content) throws CertificateException {

        // Trim extra spaces.
        String decodedContent = content.trim();

        // Remove certificate headers.
        byte[] decoded = Base64.getDecoder().decode(decodedContent
                .replaceAll(MutualTLSUtil.BEGIN_CERT, StringUtils.EMPTY)
                .replaceAll(MutualTLSUtil.END_CERT, StringUtils.EMPTY).trim()
        );

        return (java.security.cert.X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decoded));
    }

    /**
     * Remove the certificate thumbprint prefixed scope from the space delimited list of authorized scopes.
     *
     * @param scopes Authorized scopes of the token.
     * @return scopes by removing the custom scope.
     */
    private String[] getReducedResponseScopes(String[] scopes) {
        if (scopes != null && scopes.length > 0) {
            List<String> scopesList = new LinkedList<>(Arrays.asList(scopes));
            if (scopes.length == 1) {
                scopesList.add(0, "default");
            }
            scopesList.removeIf(s -> s.startsWith(MutualTLSUtil.CERT_THUMBPRINT));
            return scopesList.toArray(new String[scopesList.size()]);
        }
        return scopes;
    }
}
