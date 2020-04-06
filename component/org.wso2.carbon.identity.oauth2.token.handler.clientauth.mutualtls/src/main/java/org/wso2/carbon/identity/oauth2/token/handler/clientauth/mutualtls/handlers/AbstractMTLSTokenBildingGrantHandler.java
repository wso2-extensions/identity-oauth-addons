package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.handlers;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.CommonConstants;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class AbstractMTLSTokenBildingGrantHandler {

    private static Log log = LogFactory.getLog(MTLSTokenBindingAuthorizationCodeGrantHandler.class);

    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx, boolean validateScope) throws IdentityOAuth2Exception {

        // Get MTLS certificate from transport headers.
        HttpRequestHeader[] requestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        String headerName = IdentityUtil.getProperty(CommonConstants.MTLS_AUTH_HEADER);

        Optional<HttpRequestHeader> certHeader =
                Arrays.stream(requestHeaders).filter(httpRequestHeader ->
                        headerName.equals(httpRequestHeader.getName())).findFirst();

        String authenticatorType = (String) tokReqMsgCtx.getOauth2AccessTokenReqDTO().getoAuthClientAuthnContext()
                .getParameter(CommonConstants.AUTHENTICATOR_TYPE_PARAM);
        if (certHeader.isPresent() && CommonConstants.AUTHENTICATOR_TYPE_MTLS.equals(authenticatorType)) {
            Base64URL certThumbprint = null;
            if (log.isDebugEnabled()) {
                log.debug("Client MTLS certificate found: " + certHeader);
            }
            try {
                if (certHeader.get().getValue() != null) {
                    X509Certificate certificate = parseCertificate(certHeader.get().getValue()[0]);
                    certThumbprint = X509CertUtils.computeSHA256Thumbprint(certificate);
                }
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
                scopesList.add(CommonConstants.CERT_THUMBPRINT + "#" + CommonConstants.SHA256_DIGEST_ALGORITHM +
                        CommonConstants.CERT_THUMBPRINT_SEPARATOR + certThumbprint.toString());
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
        String decodedContent = StringUtils.trim(content);

        // Remove certificate headers.
        byte[] decoded = Base64.getDecoder().decode(StringUtils.trim(decodedContent
                .replaceAll(CommonConstants.BEGIN_CERT, StringUtils.EMPTY)
                .replaceAll(CommonConstants.END_CERT, StringUtils.EMPTY)));

        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decoded));
    }
}
