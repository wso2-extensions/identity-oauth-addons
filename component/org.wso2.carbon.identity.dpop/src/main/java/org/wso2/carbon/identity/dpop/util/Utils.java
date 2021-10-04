/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.dpop.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axiom.om.OMElement;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.core.persistence.UmPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import javax.xml.namespace.QName;

/**
 * This class provides utility functions for dpop implementation.
 */
public class Utils {

    public static JdbcTemplate getNewTemplate() {

        return new JdbcTemplate(UmPersistenceManager.getInstance().getDataSource());
    }

    public static boolean readConfigurations() {

        IdentityConfigParser configParser = IdentityConfigParser.getInstance();
        OMElement oauthElem = configParser.getConfigElement(DPoPConstants.OAUTH_CONFIG_ELEMENT);
        //Property to define dpop state
        OMElement dpopConfigElement = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(DPoPConstants
                        .DPOP_CONFIG_ELEMENT));

        if (dpopConfigElement != null) {
            OMElement dpopEnabled =
                    dpopConfigElement.getFirstChildWithName(getQNameWithIdentityNS(DPoPConstants.DPOP_ENABLED));

            if (dpopEnabled != null) {
                return Boolean.parseBoolean(dpopEnabled.getText());
            }
        }
        return false;
    }

    public static String getThumbprintOfKeyFromDpopProof(String dPopProof)
            throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJwt = SignedJWT.parse(dPopProof);
            JWSHeader header = signedJwt.getHeader();
            return getKeyThumbprintOfKey(header.getJWK().toString(), signedJwt);
        } catch (ParseException | JOSEException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
    }

    private static String getKeyThumbprintOfKey(String jwk, SignedJWT signedJwt)
            throws ParseException, JOSEException {

        JWK parseJwk = JWK.parse(jwk);
        boolean validSignature;
        if (DPoPConstants.ECDSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            ECKey ecKey = (ECKey) parseJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            validSignature = verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey), signedJwt);
            if (validSignature) {
                return computeThumbprintOfECKey(ecKey);
            }
        } else if (DPoPConstants.RSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            RSAKey rsaKey = (RSAKey) parseJwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            validSignature = verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey), signedJwt);
            if (validSignature) {
                return computeThumbprintOfRSAKey(rsaKey);
            }
        }
        return null;
    }

    public static String computeThumbprintOfRSAKey(RSAKey rsaKey) throws JOSEException {

        return rsaKey.computeThumbprint().toString();
    }

    public static String computeThumbprintOfECKey(ECKey ecKey) throws JOSEException {

        return ecKey.computeThumbprint().toString();
    }

    public static boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt)
            throws JOSEException {

        return signedJwt.verify(jwsVerifier);
    }
    
    private static QName getQNameWithIdentityNS(String localPart) {

        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }
}
