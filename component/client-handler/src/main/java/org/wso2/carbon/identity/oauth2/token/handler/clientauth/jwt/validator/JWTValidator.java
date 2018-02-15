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
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCacheEntry;
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
 * This class is used to validate the JWT which is coming along with the request.
 */
public class JWTValidator {

    private static final Log log = LogFactory.getLog(JWTValidator.class);
    public static final String FULLSTOP_DELIMITER = ".";
    public static final String DASH_DELIMITER = "-";
    public static final String KEYSTORE_FILE_EXTENSION = ".jks";
    public static final String RS = "RS";
    private boolean preventTokenReuse;
    private String validAudience;
    private String validIssuer;
    private int rejectBeforeInMinutes;
    List<String> mandatoryClaims;
    private JWTCache jwtCache;
    private boolean enableJTICache;

    private JWTStorageManager jwtStorageManager;

    public JWTValidator(boolean preventTokenReuse, String validAudience, int rejectBefore, String validIssuer,
                        List<String> mandatoryClaims, boolean enableJTICache) {

        this.preventTokenReuse = preventTokenReuse;
        this.validAudience = validAudience;
        this.validIssuer = validIssuer;
        this.jwtStorageManager = new JWTStorageManager();
        this.mandatoryClaims = mandatoryClaims;
        this.rejectBeforeInMinutes = rejectBefore;
        this.enableJTICache = enableJTICache;
        this.jwtCache = JWTCache.getInstance();
    }

    /**
     * To validate the JWT assertion.
     *
     * @param signedJWT Validate the token
     * @return true if the jwt is valid.
     * @throws IdentityOAuth2Exception
     */
    public boolean isValidAssertion(SignedJWT signedJWT) throws OAuthClientAuthnException {

        String errorMessage;

        if (signedJWT == null) {
            errorMessage = "No valid JWT assertion found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
            return logAndThrowException(errorMessage);
        }
        try {
            ReadOnlyJWTClaimsSet claimsSet = getClaimSet(signedJWT);

            if (claimsSet == null) {
                errorMessage = "Claim set is missing in the JWT assertion";
                throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
            }

            String jwtIssuer = claimsSet.getIssuer();
            String jwtSubject = resolveSubject(claimsSet);
            List<String> audience = claimsSet.getAudience();
            Date expirationTime = claimsSet.getExpirationTime();
            String jti = claimsSet.getJWTID();
            Date nbf = claimsSet.getNotBeforeTime();
            Date issuedAtTime = claimsSet.getIssueTime();
            long currentTimeInMillis = System.currentTimeMillis();
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            OAuthAppDO oAuthAppDO = getOAuthAppDO(jwtSubject);
            String consumerKey = oAuthAppDO.getOauthConsumerKey();
            String tenantDomain = oAuthAppDO.getUser().getTenantDomain();
            if (!validateMandatoryFeilds(mandatoryClaims, claimsSet)) {
                return false;
            }

            //Validate issuer and subject.
            if (!validateIssuer(jwtIssuer, consumerKey) || !validateSubject(jwtSubject, consumerKey)) {
                return false;
            }

            // Get audience.
            String validAud = getValidAudience(tenantDomain);
            long expTime = 0;
            long issuedTime = 0;
            if (expirationTime != null) {
                expTime = expirationTime.getTime();
            }
            if (issuedAtTime != null) {
                issuedTime = issuedAtTime.getTime();
            }

            //Validate signature validation, audience, nbf,exp time, jti.
            if (!validateJTI(signedJWT, jti, currentTimeInMillis, timeStampSkewMillis, expTime, issuedTime) ||
                    !validateAudience(validAud, audience) || !validateJWTWithExpTime(expirationTime, currentTimeInMillis
                    , timeStampSkewMillis) || !validateNotBeforeClaim(currentTimeInMillis, timeStampSkewMillis, nbf) ||
                    !validateAgeOfTheToken(issuedAtTime, currentTimeInMillis, timeStampSkewMillis) || !isValidSignature
                    (signedJWT, tenantDomain, jwtSubject)) {
                return false;
            }

            return true;

        } catch (IdentityOAuth2Exception e) {
            return logAndThrowException(e.getMessage());
        }
    }

    private boolean validateMandatoryFeilds(List<String> mandatoryClaims, ReadOnlyJWTClaimsSet claimsSet) throws OAuthClientAuthnException {

        for (String mandatoryClaim : mandatoryClaims) {
            if (claimsSet.getClaim(mandatoryClaim) == null) {
                String errorMessage = "Mandatory field :" + mandatoryClaim + " is missing in the JWT assertion.";
                return logAndThrowException(errorMessage);
            }
        }
        return true;
    }

    // "REQUIRED. sub. This MUST contain the client_id of the OAuth Client."
    public boolean validateSubject(String jwtSubject, String consumerKey) throws OAuthClientAuthnException {

        String errorMessage = String.format("Invalid Subject '%s' is found in the JWT. It should be equal to the '%s'",
                jwtSubject, consumerKey);
        if (!jwtSubject.trim().equals(consumerKey)) {
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new OAuthClientAuthnException("Invalid Subject: " + jwtSubject + " is found in the JWT", OAuth2ErrorCodes.
                    INVALID_REQUEST);
        }
        return true;
    }

    // "REQUIRED. iss. This MUST contain the client_id of the OAuth Client." when a valid issuer is not specified in the
    // jwtValidator.
    private boolean validateIssuer(String issuer, String consumerKey) throws OAuthClientAuthnException {

        String errorMessage = String.format("Invalid issuer '%s' is found in the JWT. It should be equal to the '%s'"
                , issuer, consumerKey);
        String error = String.format("Invalid issuer '%s' is found in the JWT. ", issuer);
        //check whether the issuer is client_id
        if (isEmpty(validIssuer)) {
            if (!issuer.trim().equals(consumerKey)) {
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
                throw new OAuthClientAuthnException(error, OAuth2ErrorCodes.INVALID_REQUEST);
            }
            return true;
        } else if (!validIssuer.equals(issuer)) {
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new OAuthClientAuthnException(error, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return true;
    }

    // "The Audience SHOULD be the URL of the Authorization Server's Token Endpoint", if a valid audience is not
    // specified.
    private boolean validateAudience(String expectedAudience, List<String> audience) throws OAuthClientAuthnException {

        for (String aud : audience) {
            if (StringUtils.equals(expectedAudience, aud)) {
                return true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("None of the audience values matched the tokenEndpoint Alias :" + expectedAudience);
        }
        throw new OAuthClientAuthnException("Failed to match audience values.", OAuth2ErrorCodes.INVALID_REQUEST);
    }

    // "REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens
    // MUST only be used once, unless conditions for reuse were negotiated between the parties; any such negotiation is
    // beyond the scope of this specification."
    private boolean validateJTI(SignedJWT signedJWT, String jti, long currentTimeInMillis,
                                long timeStampSkewMillis, long expTime, long issuedTime) throws OAuthClientAuthnException {

        if (enableJTICache) {
            JWTCacheEntry entry = jwtCache.getValueFromCache(jti);
            if (!validateJTIInCache(jti, signedJWT, entry, currentTimeInMillis, timeStampSkewMillis, this.jwtCache)) {
                return false;
            }
        }
        // Check JWT ID in DB
        if (!validateJWTInDataBase(jti, currentTimeInMillis, timeStampSkewMillis)) {
            return false;
        }
        persistJWTID(jti, expTime, issuedTime);
        return true;
    }

    private boolean validateJWTInDataBase(String jti, long currentTimeInMillis,
                                          long timeStampSkewMillis) throws OAuthClientAuthnException {

        JWTEntry jwtEntry = jwtStorageManager.getJwtFromDB(jti);
        if (jwtEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("JWT id: " + jti + " not found in the Storage the JWT has been validated successfully.");
            }
            return true;
        } else if (preventTokenReuse) {
            if (jwtStorageManager.isJTIExistsInDB(jti)) {
                String message = "JWT Token with JTI: " + jti + " has been replayed";
                return logAndThrowException(message);
            }
        } else {
            if (!checkJTIValidityPeriod(jti, jwtEntry.getExp(), currentTimeInMillis, timeStampSkewMillis)) {
                return false;
            }
        }
        return true;
    }

    private boolean checkJTIValidityPeriod(String jti, long jwtExpiryTimeMillis, long currentTimeInMillis,
                                           long timeStampSkewMillis) throws OAuthClientAuthnException {

        if (currentTimeInMillis + timeStampSkewMillis > jwtExpiryTimeMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JWT Token with jti: " + jti + "has been reused after the allowed expiry time: " +
                        jwtExpiryTimeMillis);
            }
            return true;
        } else {
            String message = "JWT Token with jti: " + jti + " has been replayed before the allowed expiry time: "
                    + jwtExpiryTimeMillis;
            return logAndThrowException(message);
        }
    }

    private void persistJWTID(final String jti, long expiryTime, long issuedTime) throws OAuthClientAuthnException {

        jwtStorageManager.persistJWTIdInDB(jti, expiryTime, issuedTime);
    }

    private OAuthAppDO getOAuthAppDO(String jwtSubject) throws OAuthClientAuthnException {

        OAuthAppDO oAuthAppDO = null;
        String message = String.format("Error while retrieving OAuth application with provided JWT information with " +
                "subject '%s' ", jwtSubject);
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(jwtSubject);
            if (oAuthAppDO == null) {
                logAndThrowException(message);
            }
        } catch (InvalidOAuthClientException e) {
            logAndThrowException(message);
        } catch (IdentityOAuth2Exception e) {
            logAndThrowException(message);
        }
        return oAuthAppDO;
    }

    private boolean logAndThrowException(String detailedMessage) throws OAuthClientAuthnException {

        if (log.isDebugEnabled()) {
            log.debug(detailedMessage);
        }
        throw new OAuthClientAuthnException(detailedMessage, OAuth2ErrorCodes.INVALID_REQUEST);
    }

    private boolean validateJWTWithExpTime(Date expTime, long currentTimeInMillis, long timeStampSkewMillis)
            throws OAuthClientAuthnException {

        long expirationTime = expTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis > expirationTime) {
            String errorMessage = "JWT Token is expired. Expired Time: " + expTime;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
        } else {
            return true;
        }
    }

    // "The JWT MAY contain an "nbf" (not before) claim that identifies
    // the time before which the token MUST NOT be accepted for
    // processing."
    private boolean validateNotBeforeClaim(long currentTimeInMillis, long timeStampSkewMillis, Date nbf) throws OAuthClientAuthnException {

        if (nbf != null) {

            if (currentTimeInMillis + timeStampSkewMillis - nbf.getTime() <= 0) {
                String message = "The token is used bfore the nbf claim value.";
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new OAuthClientAuthnException(message, OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        return true;
    }

    private boolean isValidSignature(SignedJWT signedJWT, String tenantDomain,
                                     String alias) throws OAuthClientAuthnException {

        try {
            X509Certificate cert = getCertificate(tenantDomain, alias);
            return validateSignature(signedJWT, cert);
        } catch (JOSEException e) {
            throw new OAuthClientAuthnException(e.getMessage(), OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private String getValidAudience(String tenantDomain) throws OAuthClientAuthnException {

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
            String message = "Error while loading OAuth2TokenEPUrl of the resident IDP of tenant: " + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new OAuthClientAuthnException(message, OAuth2ErrorCodes.INVALID_REQUEST);
        }

        if (isEmpty(audience)) {
            audience = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        }
        return audience;
    }

    /**
     * To retreive the processed JWT claimset.
     *
     * @param signedJWT signedJWT
     * @return JWT claim set
     * @throws IdentityOAuth2Exception
     */
    public ReadOnlyJWTClaimsSet getClaimSet(SignedJWT signedJWT) throws OAuthClientAuthnException {

        ReadOnlyJWTClaimsSet claimsSet;
        String errorMessage;
        if (signedJWT == null) {
            errorMessage = "No Valid Assertion was found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
            throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                errorMessage = "Claim values are empty in the given JSON Web Token.";
                throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (ParseException e) {
            String errorMsg = "Error when trying to retrieve claimsSet from the JWT.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new OAuthClientAuthnException(errorMsg, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return claimsSet;
    }

    /**
     * The default implementation which creates the subject from the 'sub' attribute.
     *
     * @param claimsSet all the JWT claims
     * @return The subject, to be used
     */
    public String resolveSubject(ReadOnlyJWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    private static X509Certificate getCertificate(String tenantDomain, String alias) throws OAuthClientAuthnException {

        int tenantId;
        try {
            tenantId = JWTServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error getting the tenant ID for the tenant domain : " + tenantDomain;
            throw new OAuthClientAuthnException(errorMsg, OAuth2ErrorCodes.INVALID_REQUEST);
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
            String errorMsg = "Error instantiating an X509Certificate object for the certificate alias: " + alias +
                    " in tenant:" + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new OAuthClientAuthnException(errorMsg, OAuth2ErrorCodes.INVALID_REQUEST);
        } catch (Exception e) {
            String message = "Unable to load key store manager for the tenant domain: " + tenantDomain;
            //keyStoreManager throws Exception
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new OAuthClientAuthnException(message, OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private static String generateKSNameFromDomainName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(FULLSTOP_DELIMITER, DASH_DELIMITER);
        return ksName + KEYSTORE_FILE_EXTENSION;
    }

    private boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate)
            throws JOSEException, OAuthClientAuthnException {

        JWSVerifier verifier;
        ReadOnlyJWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            throw new OAuthClientAuthnException("Unable to locate certificate for JWT " + header.toString(),
                    OAuth2ErrorCodes.INVALID_REQUEST);
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (isEmpty(alg)) {
            throw new OAuthClientAuthnException("Signature validation failed. No algorithm is found in the JWT header.",
                    OAuth2ErrorCodes.INVALID_REQUEST);
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
                    throw new OAuthClientAuthnException("Signature validation failed. Public key is not an RSA public key.",
                            OAuth2ErrorCodes.INVALID_REQUEST);
                }
            } else {
                throw new OAuthClientAuthnException("Signature Algorithm not supported : " + alg,
                        OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        // At this point 'verifier' will never be null.
        return signedJWT.verify(verifier);
    }

    private boolean validateAgeOfTheToken(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis) throws
            OAuthClientAuthnException {

        if (issuedAtTime == null) {
            return true;
        }
        if (rejectBeforeInMinutes > 0) {
            long issuedAtTimeMillis = issuedAtTime.getTime();
            long rejectBeforeMillis = 1000L * 60 * rejectBeforeInMinutes;
            if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis >
                    rejectBeforeMillis) {
                String logMsg = getTokenTooOldMessage(currentTimeInMillis, timeStampSkewMillis, issuedAtTimeMillis,
                        rejectBeforeMillis);
                if (log.isDebugEnabled()) {
                    log.debug(logMsg);
                }
                throw new OAuthClientAuthnException("The jwt is too old to use.", OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        return true;
    }

    private String getTokenTooOldMessage(long currentTimeInMillis, long timeStampSkewMillis, long issuedAtTimeMillis,
                                         long rejectBeforeMillis) {

        StringBuilder tmp = new StringBuilder();
        tmp.append("JSON Web Token is issued before the allowed time.");
        tmp.append(" Issued At Time(ms) : ");
        tmp.append(issuedAtTimeMillis);
        tmp.append(", Reject before limit(ms) : ");
        tmp.append(rejectBeforeMillis);
        tmp.append(", TimeStamp Skew : ");
        tmp.append(timeStampSkewMillis);
        tmp.append(", Current Time : ");
        tmp.append(currentTimeInMillis);
        tmp.append(". JWT Rejected and validation terminated");
        return tmp.toString();
    }

    private boolean validateJTIInCache(String jti, SignedJWT signedJWT, JWTCacheEntry entry, long currentTimeInMillis,
                                       long timeStampSkewMillis, JWTCache jwtCache) throws OAuthClientAuthnException {

        if (entry == null) {
            // Update the cache with the new JWT for the same JTI.
            jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
        } else if (preventTokenReuse) {
            throw new OAuthClientAuthnException("JWT Token with jti: " + jti + " has been replayed",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        } else {
            try {
                SignedJWT cachedJWT = entry.getJwt();
                long cachedJWTExpiryTimeMillis = cachedJWT.getJWTClaimsSet().getExpirationTime().getTime();
                if (checkJTIValidityPeriod(jti, cachedJWTExpiryTimeMillis, currentTimeInMillis, timeStampSkewMillis)) {
                    // Update the cache with the new JWT for the same JTI.
                    jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
                } else {
                    return false;
                }
            } catch (ParseException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to parse the cached jwt assertion : " + entry.getEncodedJWt());
                }
                throw new OAuthClientAuthnException("JTI validation failed.", OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT id: " + jti + " not found in the cache and the JWT has been validated " +
                    "successfully in cache.");
        }
        return true;
    }
}