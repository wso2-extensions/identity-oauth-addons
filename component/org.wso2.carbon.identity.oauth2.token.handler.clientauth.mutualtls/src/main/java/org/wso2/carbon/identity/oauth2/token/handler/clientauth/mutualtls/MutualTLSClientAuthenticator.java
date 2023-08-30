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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.AbstractOAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCacheKey;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.CommonConstants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil.JAVAX_SERVLET_REQUEST_CERTIFICATE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil.isJwksUriConfigured;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getServiceProvider;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * This class is responsible for authenticating OAuth clients with Mutual TLS. The client will present
 * client certificate presented to the authorization server during TLS handshake. As a result of successful
 * validation of the certificate at web container, the certificate will be available in request attributes. This
 * authenticator will authenticate the client by matching the certificate presented during handshake against the
 * certificate registered for the client.
 */
public class MutualTLSClientAuthenticator extends AbstractOAuthClientAuthenticator {

    private static final Log log = LogFactory.getLog(MutualTLSClientAuthenticator.class);

    /**
     * @param request                 HttpServletRequest which is the incoming request.
     * @param bodyParams              Body parameter map of the request.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @return Whether the authentication is successful or not.
     * @throws OAuthClientAuthnException
     */
    @Override
    public boolean authenticateClient(HttpServletRequest request, Map<String, List> bodyParams,
                                      OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {

        X509Certificate registeredCert;
        URL jwksUri;

        // This value is consumed by MTLS token binding to validate whether the client was authenticated using MTLS.
        oAuthClientAuthnContext.addParameter(CommonConstants.AUTHENTICATOR_TYPE_PARAM,
                CommonConstants.AUTHENTICATOR_TYPE_MTLS);

        // In case if the client ID is not set from canAuthenticate method.
        if (StringUtils.isEmpty(oAuthClientAuthnContext.getClientId())) {

            String clientId = getClientId(request, bodyParams, oAuthClientAuthnContext);
            if (StringUtils.isNotBlank(clientId)) {
                oAuthClientAuthnContext.setClientId(clientId);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Mutual TLS authenticator cannot handle this request. Client id is not available in body " +
                                       "params or valid certificate not found in request attributes.");
                }
                return false;
            }
        }

        try {
            if (log.isDebugEnabled()) {
                log.debug("Authenticating client : " + oAuthClientAuthnContext.getClientId() + " with public " +
                        "certificate.");
            }
            X509Certificate requestCert;
            Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
            Optional<X509Certificate> x509certObject = getCertificateFromHeader(request);

            if (certObject instanceof X509Certificate[]) {
                X509Certificate[] cert = (X509Certificate[]) certObject;
                requestCert = cert[0];
            } else if (certObject instanceof X509Certificate) {
                requestCert = (X509Certificate) certObject;
            } else if (x509certObject.isPresent()) {
                requestCert = x509certObject.get();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Could not find client certificate in required format for client: " +
                            oAuthClientAuthnContext.getClientId());
                }
                return false;
            }

            String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthClientAuthnContext.getClientId());
            ServiceProvider serviceProvider = getServiceProvider(oAuthClientAuthnContext.getClientId(), tenantDomain );
            if (isJwksUriConfigured(serviceProvider)) {
                if (log.isDebugEnabled()) {
                    log.debug("Public certificate not configured for Service Provider with client_id: "
                            + oAuthClientAuthnContext.getClientId() + " of tenantDomain: " + tenantDomain + ". "
                            + "Fetching the jwks endpoint for validating request certificate");
                }
                jwksUri = getJWKSEndpointOfSP(serviceProvider, oAuthClientAuthnContext.getClientId());
                return authenticate(jwksUri, requestCert);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Public certificate configured for Service Provider with client_id: "
                            + oAuthClientAuthnContext.getClientId() + " of tenantDomain: " + tenantDomain
                            + ". Using public certificate  for validating request certificate");
                }
                registeredCert = (X509Certificate) OAuth2Util
                        .getX509CertOfOAuthApp(oAuthClientAuthnContext.getClientId(), tenantDomain);
                return authenticate(registeredCert, requestCert);
            }
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.SERVER_ERROR, "Error occurred while retrieving " +
                    "public certificate of client ID: " + oAuthClientAuthnContext.getClientId(), e);
        } catch (InvalidOAuthClientException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_CLIENT, "Error occurred while retrieving " +
                    "tenant domain for the client ID: " + oAuthClientAuthnContext.getClientId(), e);
        }

    }

    /**
     * Returns whether the incoming request can be authenticated or not using the given inputs.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param bodyParams Body parameters present in the request.
     * @param context    OAuth2 client authentication context.
     * @return Whether client can be authenticated using this authenticator.
     */
    @Override
    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> bodyParams,
                                   OAuthClientAuthnContext context) {

        String headerName = IdentityUtil.getProperty(CommonConstants.MTLS_AUTH_HEADER);
        if (clientIdExistsAsParam(bodyParams) || clientIdExistsAsHeader(request)) {
            try {
                if (!isMTLSAuthentication(request, bodyParams)) {
                    return false;
                }
            } catch (OAuthClientAuthnException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while processing the request.", e);
                }
                return false;
            }
            if (validCertExistsAsAttribute(request)) {
                if (log.isDebugEnabled()) {
                    log.debug("A valid certificate was found in the request attribute hence returning true.");
                }
                return true;
            } else {
                if (StringUtils.isNotBlank(headerName) && getCertificateFromHeader(request).isPresent()) {
                    if (log.isDebugEnabled()) {
                        log.debug("A valid certificate was found from the request header hence returning true.");
                    }
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Mutual TLS authenticator cannot handle this request. " +
                                "A valid certificate could not be found in the request.");
                    }
                    return false;
                }
            }
        }  else {
            if (log.isDebugEnabled()) {
                log.debug("Mutual TLS authenticator cannot handle this request. " +
                        "Client id is not available as a parameter in body.");
            }
            return false;
        }
    }

    /**
     * Retrieves the client ID which is extracted from incoming request.
     *
     * @param request                 HttpServletRequest.
     * @param bodyParams              Body parameter map of the incoming request.
     * @param oAuthClientAuthnContext OAuthClientAuthentication context.
     * @return Client ID of the OAuth2 client.
     * @throws OAuthClientAuthnException OAuth client authentication Exception.
     */
    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        Map<String, String> stringContent = getBodyParameters(bodyParams);
        oAuthClientAuthnContext.setClientId(stringContent.get(OAuth.OAUTH_CLIENT_ID));
        return oAuthClientAuthnContext.getClientId();
    }

    private Optional<X509Certificate> getCertificateFromHeader(HttpServletRequest request) {

        String headerName = IdentityUtil.getProperty(CommonConstants.MTLS_AUTH_HEADER);
        String headerString = request.getHeader(headerName);

        if (StringUtils.isNotBlank(headerString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("%s header available in request as %s", headerName, headerString));
            }

            try {
                return Optional.of(parseCertificate(headerString));
            } catch (CertificateException e) {
                log.error("Unable to parse the certificate sent in header", e);
            }
        }

        return Optional.empty();
    }

    /**
     * Return Certificate for give Certificate Content.
     *
     * @param content   Certificate Content
     * @return X509Certificate X.509 certificate after decoding the certificate content.
     * @throws CertificateException Certificate Exception.
     */
    private X509Certificate parseCertificate(String content) throws CertificateException {

        // Trim extra spaces.
        String decodedContent = StringUtils.trim(content);

        // Remove Certificate Headers.
        byte[] decoded = Base64.getDecoder().decode(StringUtils.trim(decodedContent
                .replaceAll(CommonConstants.BEGIN_CERT, StringUtils.EMPTY)
                .replaceAll(CommonConstants.END_CERT, StringUtils.EMPTY)
        ));

        return (java.security.cert.X509Certificate) CertificateFactory.getInstance(CommonConstants.X509)
                .generateCertificate(new ByteArrayInputStream(decoded));
    }

    private boolean clientIdExistsAsParam(Map<String, List> contentParam) {

        Map<String, String> stringContent = getBodyParameters(contentParam);
        return (StringUtils.isNotEmpty(stringContent.get(OAuth.OAUTH_CLIENT_ID)));
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
            String publicKeyOfRegisteredCert = MutualTLSUtil.getThumbPrint(registeredCert, null);
            String publicKeyOfRequestCert = MutualTLSUtil.getThumbPrint(requestCert, null);
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
        } catch (CertificateEncodingException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.INVALID_GRANT, "Error occurred while " +
                    "generating certificate thumbprint. Error: " + e.getMessage(), e);
        }
        return trustedCert;
    }

    /**
     * Authenticate the client by comparing the attributes retrieved from the JWKS endpoint of the registered public
     * certificate against the public key of the certificate presented at TLS hand shake for authentication.
     *
     * @param jwksUri     JWKS URI registered at service provider configuration.
     * @param requestCert X.509 certificate presented to server during TLS hand shake.
     * @return Whether the client was successfully authenticated or not.
     */
    private boolean authenticate(URL jwksUri, X509Certificate requestCert) throws OAuthClientAuthnException {

        try {
            return isAuthenticated(getResourceContent(jwksUri), requestCert);
        } catch (IOException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error occurred while opening HTTP connection for the JWKS URL : " + jwksUri, e);
        } catch (CertificateException e) {
            throw new OAuthClientAuthnException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error occurred while parsing certificate retrieved from JWKS endpoint ", e);
        }
    }

    /**
     * Authenticate the client by iterating through the JSON Array and matching each attribute.
     *
     * @param resourceArray Json Array retrieved from JWKS endpoint
     * @param requestCert   X.509 certificate presented to server during TLS hand shake.
     * @return Whether the client was successfully authenticated or not.
     */
    private boolean isAuthenticated(JsonArray resourceArray, X509Certificate requestCert)
            throws CertificateException, OAuthClientAuthnException {

        for (JsonElement jsonElement : resourceArray) {
            JsonElement attributeValue = jsonElement.getAsJsonObject().get(CommonConstants.X5T);
            if (attributeValue != null && attributeValue.getAsString().equals(MutualTLSUtil.getThumbPrint(requestCert,
                    null))) {
                if (log.isDebugEnabled()) {
                    log.debug("Client authentication successful using the attribute: " + CommonConstants.X5T);
                }
                return true;
            }
            attributeValue = jsonElement.getAsJsonObject().get(CommonConstants.X5C);
            if (attributeValue != null) {
                CertificateFactory factory = CertificateFactory.getInstance(CommonConstants.X509);
                X509Certificate cert = (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(attributeValue.getAsString())));
                if (authenticate(cert, requestCert)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Client authentication successful using the attribute: " + CommonConstants.X5C);
                    }
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Fetch JWK Set as a String from JWKS endpoint.
     *
     * @param jwksUri JWKS Endpoint URL
     */
    public JsonArray getResourceContent(URL jwksUri) throws IOException {

        if (jwksUri != null) {

            Resource resource = null;
            MutualTLSJWKSCacheKey mutualTLSJWKSCacheKey = new MutualTLSJWKSCacheKey(jwksUri.toString());
            MutualTLSJWKSCacheEntry mutualTLSJWKSCacheEntry = MutualTLSJWKSCache.getInstance()
                    .getValueFromCache(mutualTLSJWKSCacheKey);
            if (mutualTLSJWKSCacheEntry != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieving JWKS for " + jwksUri.toString() + " from cache.");
                }
                resource = mutualTLSJWKSCacheEntry.getValue();
                if (log.isDebugEnabled() && resource != null) {
                    log.debug("Cache hit for " + jwksUri.toString());
                }
            }
            if (resource == null) {

                DefaultResourceRetriever defaultResourceRetriever;
                defaultResourceRetriever = new DefaultResourceRetriever(
                        MutualTLSUtil.readHTTPConnectionConfigValue(CommonConstants.HTTP_CONNECTION_TIMEOUT_XPATH),
                        MutualTLSUtil.readHTTPConnectionConfigValue(CommonConstants.HTTP_READ_TIMEOUT_XPATH));
                if (log.isDebugEnabled()) {
                    log.debug("Fetching JWKS from remote endpoint. JWKS URI: " + jwksUri);
                }
                resource = defaultResourceRetriever.retrieveResource(jwksUri);
                MutualTLSJWKSCache.getInstance()
                        .addToCache(mutualTLSJWKSCacheKey, new MutualTLSJWKSCacheEntry(resource));
            }
            if (resource != null) {
                JsonParser jp = new JsonParser();
                try (InputStream inputStream = new ByteArrayInputStream(
                        resource.getContent().getBytes(StandardCharsets.UTF_8));
                        InputStreamReader inputStreamReader = new InputStreamReader(inputStream)) {
                    JsonElement root = jp.parse(inputStreamReader);
                    JsonObject rootObj = root.getAsJsonObject();
                    JsonElement keys = rootObj.get(CommonConstants.KEYS);
                    if (keys != null) {
                        return keys.getAsJsonArray();
                    } else {
                        return null;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Fetch JWKS endpoint using client ID.
     *
     * @param serviceProvider Service Provider
     */
    public URL getJWKSEndpointOfSP(ServiceProvider serviceProvider, String clientID) throws OAuthClientAuthnException {

        String jwksUri;
        jwksUri = MutualTLSUtil.getPropertyValue(serviceProvider, CommonConstants.JWKS_URI);
        if (StringUtils.isEmpty(jwksUri)) {
            throw new OAuthClientAuthnException(
                    "jwks endpoint not configured for the service provider for client ID: " + clientID,
                    OAuth2ErrorCodes.SERVER_ERROR);
        }
        URL url;
        try {
            url = new URL(jwksUri);
            if (log.isDebugEnabled()) {
                log.debug("Configured JWKS URI found: " + jwksUri);
            }
        } catch (MalformedURLException e) {
            throw new OAuthClientAuthnException("URL might be malformed " + clientID, OAuth2ErrorCodes.SERVER_ERROR, e);
        }
        return url;
    }

    @Override
    public String getName() {

        return this.getClass().getSimpleName();
    }

    /**
     * Validate whether the request follows MTLS client authentication.
     *
     * @param request         Http servlet request.
     * @param contentParam    Map of request body params.
     * @return Whether the request follows MTLS client authentication.
     * @throws OAuthClientAuthnException
     */
    private boolean isMTLSAuthentication(HttpServletRequest request, Map<String, List> contentParam)
            throws OAuthClientAuthnException {

        String mtlsAuthHeader = Optional.ofNullable(IdentityUtil.getProperty(CommonConstants.MTLS_AUTH_HEADER))
                .orElse("CONFIG_NOT_FOUND");

        String oauthClientID =  request.getParameter(OAuth.OAUTH_CLIENT_ID);
        if (isEmpty(oauthClientID)) {
            oauthClientID = (String) contentParam.get(OAuth.OAUTH_CLIENT_ID).get(0);
        }
        try {
            String oauthClientSecret = request.getParameter(OAuth.OAUTH_CLIENT_SECRET);
            String oauthJWTAssertion = request.getParameter(CommonConstants.OAUTH_JWT_ASSERTION);
            String oauthJWTAssertionType = request.getParameter(CommonConstants.OAUTH_JWT_ASSERTION_TYPE);
            String authorizationHeader = request.getHeader(CommonConstants.AUTHORIZATION_HEADER);
            String x509Certificate = request.getHeader(mtlsAuthHeader);
            if (isEmpty(x509Certificate)) {
                Certificate certificate = (Certificate) request.getAttribute(mtlsAuthHeader);
                if (certificate != null) {
                    x509Certificate = IdentityUtil.convertCertificateToPEM(certificate);
                }
            }
            return (isNotEmpty(oauthClientID) && isEmpty(oauthClientSecret) && isEmpty(oauthJWTAssertion) &&
                    isEmpty(oauthJWTAssertionType) && isEmpty(authorizationHeader) && x509Certificate != null &&
                    parseCertificate(x509Certificate) != null);
        } catch (CertificateException e) {
            throw new OAuthClientAuthnException("Error occurred while parsing the certificate",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    /**
     * Check whether the Client ID is included in the request headers.
     *
     * @param request     Http servlet request.
     * @return Whether the Client ID is included in the request headers.
     */
    private boolean clientIdExistsAsHeader(HttpServletRequest request) {

        String oauthClientID =  request.getParameter(OAuth.OAUTH_CLIENT_ID);
        return (isNotEmpty(oauthClientID));
    }
}

