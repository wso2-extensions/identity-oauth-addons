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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.JWKSCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.JWKSCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.JWKSCacheKey;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Util class for OAuth 2.0 client authentication using Mutual TLS.
 */
public class MutualTLSUtil {

    private static Log log = LogFactory.getLog(MutualTLSUtil.class);
    private static final String JWKS_URI = "jwksURI";
    private static final String KEYS = "keys";
    private static final String HTTP_CONNECTION_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPConnectionTimeout";
    private static final String HTTP_READ_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPReadTimeout";

    /**
     * Attribute name for reading client certificate in the request.
     */
    public static final String JAVAX_SERVLET_REQUEST_CERTIFICATE = "javax.servlet.request.X509Certificate";

    /**
     * Helper method to retrieve the thumbprint of a X509 certificate.
     *
     * @param cert X509 certificate
     * @return Thumbprint of the X509 certificate
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    public static String getThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException,
            CertificateEncodingException {

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] certEncoded = cert.getEncoded();
        md.update(certEncoded);
        return new String(new Base64(0, null, true).encode(
                hexify(md.digest()).getBytes(Charsets.UTF_8)), Charsets.UTF_8);
    }

    /**
     * Helper method to hexify a byte array.
     *
     * @param bytes Bytes of message digest
     * @return Hexadecimal representation
     */
    public static String hexify(byte bytes[]) {

        StringBuilder builder = new StringBuilder(bytes.length * 2);
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        for (byte byteValue : bytes) {
            builder.append(hexDigits[(byteValue & 0xf0) >> 4]).append(hexDigits[byteValue & 0x0f]);
        }
        return builder.toString();
    }

    /**
     * Fetch JWKS endpoint using client ID.
     *
     * @param clientID client ID
     */
    public static URL getJWKSEndpoint(String clientID) throws OAuthClientAuthnException {

        String jwksUri = StringUtils.EMPTY;
        ServiceProviderProperty[] spProperties;
        try {
            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientID);
            spProperties = serviceProvider.getSpProperties();
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException("Error while getting the service provider for client ID " + clientID,
                    OAuth2ErrorCodes.SERVER_ERROR, e);
        }
        jwksUri = getPropertyValue(spProperties, JWKS_URI);
        if (jwksUri != null) {
            URL url;
            try {
                url = new URL(jwksUri);
            } catch (MalformedURLException e) {
                throw new OAuthClientAuthnException("URL might be malformed " + clientID, OAuth2ErrorCodes.SERVER_ERROR,
                        e);
            }
            return url;

        } else {
            throw new OAuthClientAuthnException(
                    "jwks endpoint not configured for the service provider for client ID" + clientID,
                    OAuth2ErrorCodes.SERVER_ERROR);
        }

    }
    /**
     * Fetch JWK Set as a String from JWKS endpoint.
     *
     * @param jwksUri JWKS Endpoint URL
     */
    public static String getResourceContent(URL jwksUri) throws IOException {

        if (jwksUri != null) {

            Resource resource = null;
            JWKSCacheKey jwksCacheKey = new JWKSCacheKey(jwksUri.toString());
            JWKSCacheEntry jwksCacheEntry = JWKSCache.getInstance().getValueFromCache(jwksCacheKey);
            if (jwksCacheEntry != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrieving JWKS for " + jwksUri.toString() + " from cache.");
                }
                resource = jwksCacheEntry.getValue();
                if (log.isDebugEnabled() && resource != null) {
                    log.debug("Cache hit for " + jwksUri.toString());
                }
            }
            if (resource == null) {

                DefaultResourceRetriever defaultResourceRetriever;
                defaultResourceRetriever = new DefaultResourceRetriever(
                        readHTTPConnectionConfigValue(HTTP_CONNECTION_TIMEOUT_XPATH),
                        readHTTPConnectionConfigValue(HTTP_READ_TIMEOUT_XPATH));
                if (log.isDebugEnabled()) {
                    log.debug("Fetching JWKS from remote endpoint.");
                }
                resource = defaultResourceRetriever.retrieveResource(jwksUri);
                JWKSCache.getInstance().addToCache(jwksCacheKey, new JWKSCacheEntry(resource));
            }
            if (resource != null) {
                return resource.getContent();
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    /**
     * Convert resource to a JsonArray.
     *
     * @param resource Resource Content received from JWKS endpoint
     */
    public static JsonArray getJsonArray(String resource) {
        JsonParser jp = new JsonParser();
        InputStream inputStream = new ByteArrayInputStream(resource.getBytes(StandardCharsets.UTF_8));
        JsonElement root = jp.parse(new InputStreamReader(inputStream));
        JsonObject rootobj = root.getAsJsonObject();
        JsonElement keys = rootobj.get(KEYS);
        if (keys != null) {
            JsonArray jsonArray = keys.getAsJsonArray();
            return jsonArray;
        } else {
            return null;
        }

    }


    /**
     * Read HTTP connection configurations from identity.xml file.
     *
     * @param xPath xpath of the config property.
     * @return Config property value.
     */
    private static int readHTTPConnectionConfigValue(String xPath) {

        int configValue = 0;
        String config = IdentityUtil.getProperty(xPath);
        if (StringUtils.isNotBlank(config)) {
            try {
                configValue = Integer.parseInt(config);
            } catch (NumberFormatException e) {
                log.error("Provided HTTP connection config value in " + xPath + " should be an integer type. Value : "
                        + config);
            }
        }
        return configValue;
    }

    /**
     * Checking Whether JWKS URI configured in the UI or not.
     *
     * @param clientID     client id of the service provider.
     * @param tenantDomain tenant domain.
     * @return true if jwks uri configured.
     */
    public static boolean isJwksUriConfigured(String clientID, String tenantDomain) throws IdentityOAuth2Exception {
        ServiceProviderProperty[] serviceProviderProperties = OAuth2Util.getServiceProvider(clientID, tenantDomain)
                .getSpProperties();
        for (ServiceProviderProperty sp : serviceProviderProperties) {
            if (sp.getName().equals(JWKS_URI) && StringUtils.isNotBlank(sp.getValue())) {
                return true;
            }
        }
        return false;
    }


    /**
     * Obtaining Property value from a service provider property array
     *
     * @param properties   Service provider property array.
     * @param propertyName property name.
     * @return property value
     */
    public static String getPropertyValue(ServiceProviderProperty[] properties, String propertyName) {

        if (ArrayUtils.isEmpty(properties) || StringUtils.isBlank(propertyName)) {
            return null;
        }
        for (ServiceProviderProperty property : properties) {
            if (property == null) {
                continue;
            }
            if (propertyName.equals(property.getName())) {
                if (property != null) {
                    if (StringUtils.isNotBlank(property.getValue())) {
                        return property.getValue();
                    }
                }
            }
        }
        return null;
    }
}

