/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTStorageManager;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

/**
 * To Validate a given JWT
 */
public class JWTValidator {

    private static final Log log = LogFactory.getLog(JWTValidator.class);
    public static final String FULLSTOP_DELIMITER = ".";
    public static final String DASH_DELIMITER = "-";
    public static final String KEYSTORE_FILE_EXTENSION = ".jks";
    public static final String RS = "RS";
    private int notAcceptBeforeTimeInMins;
    private boolean preventTokenReuse;
    private String validAudience;
    private String validIssuer;
    List<Object> mandatoryClaims;

    private JWTStorageManager jwtStorageManager;

    public JWTValidator(int rejectBeforePeriod, boolean preventTokenReuse, String validAudience, String validIssuer,
                        List<Object> mandatoryClaims) {

        this.notAcceptBeforeTimeInMins = rejectBeforePeriod;
        this.preventTokenReuse = preventTokenReuse;
        this.validAudience = validAudience;
        this.validIssuer = validIssuer;
        this.jwtStorageManager = new JWTStorageManager();
        this.mandatoryClaims = mandatoryClaims;
    }

    /**
     * @param signedJWT Validate the token
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean isValidAssertion(SignedJWT signedJWT) throws OAuthClientAuthnException {

        String errorMessage;

        if (signedJWT == null) {
            errorMessage = "No valid JWT assertion found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        ReadOnlyJWTClaimsSet claimsSet;
        try {
            claimsSet = getClaimSet(signedJWT);

            if (claimsSet == null) {
                errorMessage = "Claim set is missing in the JWT assertion";
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
                throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
            }
            String jwtIssuer = claimsSet.getIssuer();
            String jwtSubject = resolveSubject(claimsSet);
            List<String> audience = claimsSet.getAudience();
            Date expirationTime = claimsSet.getExpirationTime();
            String jti = claimsSet.getJWTID();
            addMandatoryClaims(jwtIssuer, jwtSubject, audience, expirationTime, jti);

            Date notBeforeTime = claimsSet.getNotBeforeTime();
            Date issuedAtTime = claimsSet.getIssueTime();

            long currentTimeInMillis = System.currentTimeMillis();
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            OAuthAppDO oAuthAppDO = getOAuthAppDO(jwtSubject);
            String tenantDomain = oAuthAppDO.getUser().getTenantDomain();

            if (!validateIssuer(jwtIssuer, oAuthAppDO) || !validateSubject(jwtSubject)) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid jwtIssuer: " + jwtIssuer + " or jwtSubject: " + jwtSubject + " is found in the assertion." +
                            " Expected value for issuer and subject is: " + oAuthAppDO.getOauthConsumerKey());
                }
                return false;
            }
            //Validate assertion claims
            String validAud = getValidAudience(tenantDomain);

            if (!validateMandatoryFeilds(mandatoryClaims)
                    || !validateAudience(validAud, audience) || !checkNotBeforeTime(notBeforeTime, currentTimeInMillis,
                    timeStampSkewMillis) || !validateAgeOfTheToken(issuedAtTime, currentTimeInMillis, timeStampSkewMillis)
                    || !validateJWTWithExpTime(expirationTime,
                    currentTimeInMillis, timeStampSkewMillis) || !isValidSignature(signedJWT, tenantDomain, jwtSubject) ||
                    !validateJTI(jti, currentTimeInMillis, timeStampSkewMillis, expirationTime.getTime(), issuedAtTime.
                            getTime()) || !isValidSignature(signedJWT, tenantDomain, jwtSubject)) {
                return false;
            }

            return true;

        } catch (IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException(e.getMessage(), OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private void addMandatoryClaims(String jwtIssuer, String jwtSubject, List<String> audience, Date expirationTime, String jti) {

        mandatoryClaims.add(jwtIssuer);
        mandatoryClaims.add(jwtSubject);
        mandatoryClaims.add(audience);
        mandatoryClaims.add(expirationTime);
        mandatoryClaims.add(jti);
    }

    private boolean validateMandatoryFeilds(List<Object> mandatoryClaims) throws IdentityOAuth2Exception {

        for (Object mandotaryClaim : mandatoryClaims) {
            if (mandotaryClaim == null) {
                String errorMessage = "Mandatory field/feilds (Issuer, Subject, Expiration time , JWT ID or " +
                        "Audience) are missing in the JWT assertion";
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
                throw new IdentityOAuth2Exception(errorMessage);
            }
        }
        return true;
    }

    public boolean validateSubject(String jwtSubject) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = getOAuthAppDO(jwtSubject);
        return validateWithClientId(jwtSubject, oAuthAppDO);
    }

    private boolean validateIssuer(String issuer, OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {
        //check whether the issuer is client_id
        if (isEmpty(validIssuer)) {
            return validateWithClientId(issuer, oAuthAppDO);
        } else if (isNotEmpty(validIssuer) && !validIssuer.equals(issuer)) {
            String errorMessage = "Invalid field :" + issuer + " is found in the JWT. It should be equal to the: " +
                    validIssuer;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new IdentityOAuth2Exception(errorMessage);
        }
        return true;
    }

    private Boolean validateWithClientId(String jwtClaim, OAuthAppDO oAuthAppDO) throws IdentityOAuth2Exception {

        if (oAuthAppDO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to find OAuth application for provided JWT claim:" + jwtClaim);
            }
            throw new IdentityOAuth2Exception("The issuer or the subject of the assertion is invalid.");
        }
        String consumerKey = oAuthAppDO.getOauthConsumerKey();
        if (isEmpty(jwtClaim) && !jwtClaim.equals(consumerKey)) {
            String errorMessage = "Invalid field :" + jwtClaim + " is found in the JWT. It should be equal to the: " +
                    consumerKey;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new IdentityOAuth2Exception(errorMessage);
        }
        return true;
    }

    private boolean validateAudience(String tokenEP, List<String> audience) throws IdentityOAuth2Exception {

        for (String aud : audience) {
            if (StringUtils.equals(tokenEP, aud)) {
                return true;
            }
        }
        String errorMessage = "None of the audience values matched the tokenEndpoint Alias:" + tokenEP;
        if (log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        throw new IdentityOAuth2Exception(errorMessage);
    }

    private boolean validateJTI(String jti, long currentTimeInMillis,
                                long timeStampSkewMillis, long expTime, long issuedTime) throws IdentityOAuth2Exception {

        if (jti == null) {
            String message = "JTI cannot be found in the Assertion.";
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new IdentityOAuth2Exception(message);
        }
        // Check JWT ID in DB
        if (!validateJWTInDataBase(jti, currentTimeInMillis, timeStampSkewMillis)) {
            return false;
        }
        persistJWTID(jti, expTime, issuedTime);
        return true;
    }

    private boolean validateJWTInDataBase(String jti, long currentTimeInMillis,
                                          long timeStampSkewMillis) throws IdentityOAuth2Exception {

        JWTEntry jwtEntry = jwtStorageManager.getJwtFromDB(jti);
        if (jwtEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("JWT id: " + jti + " not found in the Storage the JWT has been validated successfully.");
            }
            return true;
        } else if (preventTokenReuse) {
            if (jwtStorageManager.getJwtFromDB(jti) != null) {
                String message = "JWT Token with JTI: " + jti + " has been replayed";
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new IdentityOAuth2Exception(message);
            }
        } else {
            if (!checkJTIValidityPeriod(jti, jwtEntry.getExp(), currentTimeInMillis, timeStampSkewMillis)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkJTIValidityPeriod(String jti, long jwtExpiryTimeMillis, long currentTimeInMillis,
                                           long timeStampSkewMillis) throws IdentityOAuth2Exception {

        if (currentTimeInMillis + timeStampSkewMillis > jwtExpiryTimeMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JWT Token with jti: " + jti + "has been reused after the allowed expiry time:" + jwtExpiryTimeMillis);
            }
            return true;
        } else {
            String message = "JWT Token with jti: " + jti + " Has been replayed before the allowed expiry time:"
                    + jwtExpiryTimeMillis;
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new IdentityOAuth2Exception(message);
        }
    }

    private void persistJWTID(final String jti, long expiryTime, long issuedTime) throws IdentityOAuth2Exception {

        jwtStorageManager.persistJWTIdInDB(jti, expiryTime, issuedTime);
    }

    private OAuthAppDO getOAuthAppDO(String jwtSubject) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(jwtSubject);
        } catch (InvalidOAuthClientException e) {
            String message = "Error while retrieving OAuth application with provided JWT information with subject:";
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new IdentityOAuth2Exception(message + jwtSubject, e);
        }
        return oAuthAppDO;
    }

    private boolean validateJWTWithExpTime(Date expTime, long currentTimeInMillis, long timeStampSkewMillis)
            throws IdentityOAuth2Exception {

        long expirationTime = expTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis > expirationTime) {
            String errorMessage = "JWT Token is expired. Expired Time: " + expTime;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new IdentityOAuth2Exception(errorMessage);
        } else {
            return true;
        }
    }

    private boolean checkNotBeforeTime(Date notBeforeTime, long currentTimeInMillis, long timeStampSkewMillis) throws
            IdentityOAuth2Exception {

        if (notBeforeTime == null) {
            return true;
        }
        long notBeforeTimeMillis = notBeforeTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis >= notBeforeTimeMillis) {
            return true;
        } else {
            String message = "NotBeforeTime check is failed. Token is used before the intended time. " +
                    "nbf: " + notBeforeTime;
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new IdentityOAuth2Exception(message);
        }
    }

    private boolean validateAgeOfTheToken(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis) throws
            IdentityOAuth2Exception {

        if (issuedAtTime == null) {
            return true;
        }
        if (notAcceptBeforeTimeInMins > 0) {
            long issuedAtTimeMillis = issuedAtTime.getTime();
            long rejectBeforeMillis = 1000L * 60 * notAcceptBeforeTimeInMins;
            if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis >
                    rejectBeforeMillis) {
                String logMsg = getTokenTooOldMessage(currentTimeInMillis, timeStampSkewMillis, issuedAtTimeMillis,
                        rejectBeforeMillis);
                if (log.isDebugEnabled()) {
                    log.debug(logMsg);
                }
                throw new IdentityOAuth2Exception("The assertion is too old to use.");
            }
        }
        return true;
    }

    private String getTokenTooOldMessage(long currentTimeInMillis, long timeStampSkewMillis, long issuedAtTimeMillis, long rejectBeforeMillis) {

        StringBuilder logString = new StringBuilder();
        logString.append("JSON Web Token is issued before the allowed time.");
        logString.append(" Issued At Time(ms) : ");
        logString.append(issuedAtTimeMillis);
        logString.append(", Reject before limit(ms) : ");
        logString.append(rejectBeforeMillis);
        logString.append(", TimeStamp Skew : ");
        logString.append(timeStampSkewMillis);
        logString.append(", Current Time : ");
        logString.append(currentTimeInMillis);
        logString.append(". JWT Rejected and validation terminated");
        return logString.toString();
    }

    private boolean isValidSignature(SignedJWT signedJWT, String tenantDomain,
                                     String alias) throws IdentityOAuth2Exception {

        try {
            X509Certificate cert = getCertificate(tenantDomain, alias);
            return validateSignature(signedJWT, cert);
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
    }

    private String getValidAudience(String tenantDomain) throws IdentityOAuth2Exception {

        if (isNotEmpty(validAudience)) {
            return validAudience;
        }
        String audience = null;
        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance()
                    .getResidentIdP(tenantDomain);
            FederatedAuthenticatorConfig oidcFedAuthn = IdentityApplicationManagementUtil
                    .getFederatedAuthenticator(residentIdP.getFederatedAuthenticatorConfigs(),
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);
            audience = IdentityApplicationManagementUtil.getProperty(oidcFedAuthn.getProperties(),
                    IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL).getValue();
        } catch (IdentityProviderManagementException e) {
            String message = "Error while loading OAuth2TokenEPUrl of the resident IDP of tenant:" + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new IdentityOAuth2Exception(message, e);
        }

        if (isEmpty(audience)) {
            audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        }
        return audience;
    }

    public ReadOnlyJWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        ReadOnlyJWTClaimsSet claimsSet;
        String errorMessage;
        if (signedJWT == null) {
            errorMessage = "No Valid Assertion was found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
            throw new IdentityOAuth2Exception(errorMessage);
        }
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                errorMessage = "Claim values are empty in the given JSON Web Token.";
                throw new IdentityOAuth2Exception(errorMessage);
            }
        } catch (ParseException e) {
            String errorMsg = "Error when trying to retrieve claimsSet from the JWT.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        return claimsSet;
    }

    /**
     * the default implementation creates the subject from the Sub attribute.
     * To translate between the federated and local user store, this may need some mapping.
     * Override if needed
     *
     * @param claimsSet all the JWT claims
     * @return The subject, to be used
     */
    public String resolveSubject(ReadOnlyJWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    private static X509Certificate getCertificate(String tenantDomain, String alias) throws IdentityOAuth2Exception {

        int tenantId;
        try {
            tenantId = JWTServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error getting the tenant ID for the tenant domain : " + tenantDomain;
            throw new IdentityOAuth2Exception(errorMsg, e);
        }

        KeyStoreManager keyStoreManager;
        // get an instance of the corresponding Key Store Manager instance
        keyStoreManager = KeyStoreManager.getInstance(tenantId);
        KeyStore keyStore;
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {// for tenants, load key from their generated key store
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
            } else {
                // for super tenant, load the default pub. cert using the config. in carbon.xml
                keyStore = keyStoreManager.getPrimaryKeyStore();
            }
            return (X509Certificate) keyStore.getCertificate(alias);

        } catch (KeyStoreException e) {
            String errorMsg = "Error instantiating an X509Certificate object for the certificate alias:" + alias +
                    " in tenant:" + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new IdentityOAuth2Exception(errorMsg, e);
        } catch (Exception e) {
            String message = "Unable to load key store manager for the tenant domain:" + tenantDomain;
            //keyStoreManager throws Exception
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new IdentityOAuth2Exception(message, e);
        }
    }

    private static String generateKSNameFromDomainName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(FULLSTOP_DELIMITER, DASH_DELIMITER);
        return ksName + KEYSTORE_FILE_EXTENSION;
    }

    private boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate)
            throws JOSEException, IdentityOAuth2Exception {

        JWSVerifier verifier;
        ReadOnlyJWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            throw new IdentityOAuth2Exception("Unable to locate certificate for JWT " + header.toString());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (isEmpty(alg)) {
            throw new IdentityOAuth2Exception("Signature validation failed. No algorithm is found in the JWT header.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.indexOf(RS) == 0) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new IdentityOAuth2Exception("Signature validation failed. Public key is not an RSA public key.");
                }
            } else {
                throw new IdentityOAuth2Exception("Signature Algorithm not supported yet : " + alg);
            }
        }
        // At this point 'verifier' will never be null;
        return signedJWT.verify(verifier);
    }

}
