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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Util class for OAuth 2.0 client authentication using Mutual TLS.
 */
public class MutualTLSUtil {

    private static final Log log = LogFactory.getLog(MutualTLSUtil.class);

    /**
     * Attribute name for reading client certificate in the request.
     */
    public static final String JAVAX_SERVLET_REQUEST_CERTIFICATE = "javax.servlet.request.X509Certificate";

    /**
     * Helper method to retrieve the thumbprint of a X509 certificate.
     *
     * @deprecated Use the method {@link #getThumbPrint(X509Certificate, String)} which honour OAuth2 module.
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
     * Helper method to retrieve the thumbprint of a X509 certificate.
     *
     * @param cert X509 certificate
     * @return Thumbprint of the X509 certificate
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    public static String getThumbPrint(X509Certificate cert, String alias) throws CertificateEncodingException {

        try {
            return OAuth2Util.getThumbPrint(cert, alias);
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("An error occurred while getting the thumbprint of the certificate: " + cert.toString());
            }
            throw new CertificateEncodingException("Error occurred while getting certificate thumbprint", e);
        }
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
     * Read HTTP connection configurations from identity.xml file.
     *
     * @param xPath xpath of the config property.
     * @return Config property value.
     */
    public static int readHTTPConnectionConfigValue(String xPath) {

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
     * @param serviceProvider service provider.
     * @return true if jwks uri configured.
     */
    public static boolean isJwksUriConfigured(ServiceProvider serviceProvider) {

        ServiceProviderProperty[] serviceProviderProperties = serviceProvider.getSpProperties();
        for (ServiceProviderProperty sp : serviceProviderProperties) {
            if (sp.getName().equals(CommonConstants.JWKS_URI) && StringUtils.isNotBlank(sp.getValue())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Obtaining Property value from a service provider property array
     *
     * @param serviceProvider Service provider.
     * @param propertyName    property name.
     * @return property value
     */
    public static String getPropertyValue(ServiceProvider serviceProvider, String propertyName) {

        ServiceProviderProperty[] properties = serviceProvider.getSpProperties();
        if (ArrayUtils.isEmpty(properties) || StringUtils.isBlank(propertyName)) {
            return null;
        }
        for (ServiceProviderProperty property : properties) {
            if (propertyName.equals(property.getName()) && StringUtils.isNotBlank(property.getValue())) {
                return property.getValue();
            }
        }
        return null;
    }
}

