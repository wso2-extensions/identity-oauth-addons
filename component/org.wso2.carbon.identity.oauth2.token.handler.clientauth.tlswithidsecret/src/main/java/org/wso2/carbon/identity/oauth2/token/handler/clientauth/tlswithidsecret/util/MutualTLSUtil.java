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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Util class for OAuth 2.0 client authentication using Mutual TLS.
 */
public class MutualTLSUtil {

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
        return hexify(md.digest());
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
}
