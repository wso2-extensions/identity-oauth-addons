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
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage.JWTEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage.JWTStorageManager;
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
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

/**
 * To Validate a given JWT
 */
public class JWTValidator {

    private static final Log log = LogFactory.getLog(JWTValidator.class);
    private int notAcceptBeforeTimeInMins;
    private JWTCache jwtCache;
    private boolean enableJTICache;
    private boolean preventTokenReuse;
    private String validAudience;
    private String validIssuer;

    private JWTStorageManager jwtStorageManager;

    public JWTValidator(int rejectBeforePeriod, boolean preventTokenReuse,
                        boolean enableJTICache, String validAudience, String validIssuer) {
        this.notAcceptBeforeTimeInMins = rejectBeforePeriod;
        this.preventTokenReuse = preventTokenReuse;
        this.enableJTICache = enableJTICache;
        this.validAudience = validAudience;
        this.validIssuer = validIssuer;
        jwtStorageManager = new JWTStorageManager();
        if (enableJTICache) {
            this.jwtCache = JWTCache.getInstance();
        }
    }

    /**
     * @param signedJWT return whether the token is valid
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean isValidToken(SignedJWT signedJWT) throws IdentityOAuth2Exception {
        try {
            return validateToken(signedJWT);
        } catch (IdentityOAuth2Exception e) {
            return false;
        }
    }

    /**
     * @param signedJWT Validate the token
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean validateToken(SignedJWT signedJWT) throws IdentityOAuth2Exception {
        String tokenEndPointAlias;
        ReadOnlyJWTClaimsSet claimsSet;
        String tenantDomain;

        if (signedJWT == null) {
            return invalidateToken("No Valid Assertion was found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE);
        }
        claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            return invalidateToken("Claim values are empty in the given JSON Web Token.");
        }

        String jwtIssuer = claimsSet.getIssuer();
        String jwtSubject = resolveSubject(claimsSet);
        List<String> audience = claimsSet.getAudience();
        Date expirationTime = claimsSet.getExpirationTime();
        Date notBeforeTime = claimsSet.getNotBeforeTime();
        Date issuedAtTime = claimsSet.getIssueTime();
        String jti = claimsSet.getJWTID();
        Map<String, Object> customClaims = claimsSet.getCustomClaims();
        boolean signatureValid;
        long currentTimeInMillis = System.currentTimeMillis();
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;

        if (isEmpty(jwtIssuer) || isEmpty(jwtSubject) || expirationTime == null || audience ==
                null || (preventTokenReuse && jti == null)) {
            return invalidateToken("Mandatory fields(Issuer, Subject, Expiration time , " +
                    "JWT ID or Audience) are empty in the given JSON Web Token.");
        }

        if (isNotEmpty(validIssuer) && !validIssuer.equals(jwtIssuer)) {
            return invalidateToken("Invalid Issuer:" + jwtIssuer + " in the given JSON Web Token.");
        }

        if (!validateJTI(signedJWT, jti, currentTimeInMillis, timeStampSkewMillis, expirationTime.getTime(),
                issuedAtTime.getTime())) {
            return false;
        }

        //validate whether the subject is client_id
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(jwtSubject);
        } catch (InvalidOAuthClientException e) {
            handleException("Error while retrieving OAuth application with provided JWT information with subject:" +
                    jwtSubject);
        }

        if (oAuthAppDO == null) {
            return invalidateToken("Unable to find OAuth application with provided JWT information.");
        }

        if (isEmpty(validIssuer) && !jwtIssuer.equals(oAuthAppDO.getOauthConsumerKey())) {
            return invalidateToken("Invalid field Issuer:" + jwtIssuer + " in the given JSON Web Token.");
        }

        tenantDomain = oAuthAppDO.getUser().getTenantDomain();

        //validate signature
        try {
            X509Certificate cert = getCertificate(tenantDomain, jwtSubject);
            signatureValid = validateSignature(signedJWT, cert);
            if (!signatureValid) {
                return invalidateToken("Signature or Message Authentication invalid.");
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Issuer(iss) of the JWT validated successfully. ");
                }
            }
        } catch (JOSEException e) {
            handleException("Error when verifying signature.");
        }

        //validate audience
        tokenEndPointAlias = getTokenEndpointAlias(tenantDomain);
        if (!validateAudience(tokenEndPointAlias, audience)) {
            return false;
        }

        //Check token Expiry
        if (!validateExpirationTime(expirationTime, currentTimeInMillis, timeStampSkewMillis)) {
            return false;
        }

        //check notbefore time
        if (notBeforeTime == null) {
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) not found in JWT. Continuing Validation");
            }
        } else {
            if (!checkNotBeforeTime(notBeforeTime, currentTimeInMillis, timeStampSkewMillis)) {
                return false;
            }
        }

        //check issued time
        if (issuedAtTime == null) {
            if (log.isDebugEnabled()) {
                log.debug("Issued At Time(iat) not found in JWT. Continuing Validation");
            }
        } else {
            if (!validateAgeOfTheToken(issuedAtTime, currentTimeInMillis, timeStampSkewMillis)) {
                return false;
            }
        }

        // validate custom claims
        if (customClaims == null) {
            if (log.isDebugEnabled()) {
                log.debug("No custom claims found. Continue validating other claims.");
            }
        } else {
            if (!validateCustomClaims(claimsSet.getCustomClaims())) {
                return false;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Token was validated successfully");
        }

        if (enableJTICache) {
            jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT Token was added to the cache successfully");
        }
// TODO
// persistJWTID(jti, expirationTime.getTime(), issuedAtTime.getTime());
        return true;
    }

    /**
     * Validate whether the JWT id replayed and replaying is accepted based on given conditions
     * @param signedJWT
     * @param jti
     * @param currentTimeInMillis
     * @param timeStampSkewMillis
     * @param expTime
     * @param issuedTime
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean validateJTI(SignedJWT signedJWT, String jti, long currentTimeInMillis,
                               long timeStampSkewMillis, long expTime, long issuedTime) throws IdentityOAuth2Exception {
        //check whether the token is already used
        //check JWT ID in cache
        //TODO
        if (jti == null) {
            return true;
        }
        if (enableJTICache) {
            JWTCacheEntry entry = (JWTCacheEntry) jwtCache.getValueFromCache(jti);
            if (!validateJTIInCache(jti, signedJWT, entry, currentTimeInMillis, timeStampSkewMillis, this.jwtCache)) {
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("List of used JSON Web Token IDs are not maintained in cache. Continue Validation");
            }
        }
        // check JWT ID in DB
        if (!validateJwtInDataBase(jti, currentTimeInMillis, timeStampSkewMillis)) {
            return false;
        }
        persistJWTID(jti, expTime, issuedTime);
        return true;
    }

    /**
     * Check whether the Token is indented for the server
     * @param currentAudience
     * @param audience
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean validateAudience(String currentAudience, List<String> audience) throws IdentityOAuth2Exception {
        for (String aud : audience) {
            if (StringUtils.equals(currentAudience, aud)) {
                if (log.isDebugEnabled()) {
                    log.debug(currentAudience + " is found in the list of audiences.");
                }
                return true;
            }
        }
        return invalidateToken("None of the audience values matched the tokenEndpoint Alias " + currentAudience);
    }

    /**
     * Get the token endpoint of the server
     * @param tenantDomain
     * @return
     * @throws IdentityOAuth2Exception
     */
    public String getTokenEndpointAlias(String tenantDomain) throws IdentityOAuth2Exception {
        if (isNotEmpty(validAudience)) {
            return validAudience;
        }
        String tokenEndPointAlias = null;
        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance()
                    .getResidentIdP(tenantDomain);
            FederatedAuthenticatorConfig oidcFedAuthn = IdentityApplicationManagementUtil
                    .getFederatedAuthenticator(residentIdP.getFederatedAuthenticatorConfigs(),
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);
            tokenEndPointAlias = IdentityApplicationManagementUtil.getProperty(oidcFedAuthn.getProperties(),
                    IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL).getValue();
        } catch (IdentityProviderManagementException e) {
            handleException("Error while loading OAuth2TokenEPUrl of the resident IDP of tenant:" + tenantDomain);
        }

        if (isEmpty(tokenEndPointAlias)) {
            tokenEndPointAlias = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        }
        return tokenEndPointAlias;
    }


    /**
     * @param errorMessage
     * @return
     * @throws IdentityOAuth2Exception
     */
    private boolean handleException(String errorMessage) throws IdentityOAuth2Exception {
        log.error(errorMessage);
        throw new IdentityOAuth2Exception(errorMessage);
    }

    /**
     * Invalid token message is logged and returns false
     * @param errorMessage
     * @return
     */
    private boolean invalidateToken(String errorMessage) {
        if (log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        return false;
    }

    /**
     * @param signedJWT Signed JWT
     * @return Claim set
     */
    public ReadOnlyJWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {
        ReadOnlyJWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            handleException("Error when trying to retrieve claimsSet from the JWT");
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


    /**
     * Get the X509CredentialImpl object for a particular tenant and alias
     *
     * @param tenantDomain tenant domain of the issuer
     * @param alias        alias of cert
     * @return X509Certificate object containing the public certificate in the primary keystore of the tenantDOmain
     * with alias
     */
    public static X509Certificate getCertificate(String tenantDomain, String alias) throws IdentityOAuth2Exception {

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
            if (tenantId != -1234) {// for tenants, load key from their generated key store
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
            } else {
                // for super tenant, load the default pub. cert using the
                // config. in carbon.xml
                keyStore = keyStoreManager.getPrimaryKeyStore();
            }
            return (X509Certificate) keyStore.getCertificate(alias);

        } catch (KeyStoreException e) {
            String errorMsg = "Error instantiating an X509Certificate object for the certificate alias:" + alias +
                    " in tenant:" + tenantDomain;
            log.error(errorMsg, e);
            throw new IdentityOAuth2Exception(errorMsg, e);
        } catch (Exception e) {
            //keyStoreManager throws Exception
            log.error("Unable to load key store manager for the tenant domain:" + tenantDomain, e);
            throw new IdentityOAuth2Exception("Unable to load key store manager for the tenant domain:" + tenantDomain, e);
        }
    }

    /**
     * Generate the key store name from the domain name
     *
     * @param tenantDomain tenant domain name
     * @return key store file name
     */
    public static String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(".", "-");
        return ksName + ".jks";
    }

    /**
     * Method to validate the signature of the JWT
     *
     * @param signedJWT signed JWT whose signature is to be verified
     * @return whether signature is valid, true if valid else false
     * @throws com.nimbusds.jose.JOSEException
     * @throws org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception
     */
    public boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate)
            throws JOSEException, IdentityOAuth2Exception {

        JWSVerifier verifier = null;
        ReadOnlyJWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            handleException("Unable to locate certificate for JWT " + header.toString());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (isEmpty(alg)) {
            return invalidateToken("Algorithm must not be null.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the JWT Header: " + alg);
            }
            if (alg.indexOf("RS") == 0) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    return invalidateToken("Public key is not an RSA public key.");
                }
            } else {
                return invalidateToken("Signature Algorithm not supported yet : " + alg);
            }
            if (verifier == null) {
                return invalidateToken("Could not create a signature verifier for algorithm type: " + alg);
            }
        }
        // At this point 'verifier' will never be null;
        return signedJWT.verify(verifier);
    }

    /**
     * The JWT MUST contain an exp (expiration) claim that limits the time window during which
     * the JWT can be used. The authorization server MUST reject any JWT with an expiration time
     * that has passed, subject to allowable clock skew between systems. Note that the
     * authorization server may reject JWTs with an exp claim value that is unreasonably far in the
     * future.
     *
     * @param expirationTime      Expiration time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    public boolean validateExpirationTime(Date expirationTime, long currentTimeInMillis,
                                          long timeStampSkewMillis) throws IdentityOAuth2Exception {
        long expirationTimeInMillis = expirationTime.getTime();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            return invalidateToken("JSON Web Token is expired." +
                    " Expiration Time(ms) : " + expirationTimeInMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        if (log.isDebugEnabled()) {
            log.debug("Expiration Time(exp) of JWT was validated successfully.");
        }
        return true;
    }

    /**
     * The JWT MAY contain an nbf (not before) claim that identifies the time before which the
     * token MUST NOT be accepted for processing.
     *
     * @param notBeforeTime       Not before time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    public boolean checkNotBeforeTime(Date notBeforeTime, long currentTimeInMillis, long timeStampSkewMillis) throws
            IdentityOAuth2Exception {
        long notBeforeTimeMillis = notBeforeTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
            return invalidateToken("JSON Web Token is used before Not_Before_Time." +
                    " Not Before Time(ms) : " + notBeforeTimeMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        if (log.isDebugEnabled()) {
            log.debug("Not Before Time(nbf) of JWT was validated successfully.");
        }
        return true;
    }

    /**
     * The JWT MAY contain an iat (issued at) claim that identifies the time at which the JWT was
     * issued. Note that the authorization server may reject JWTs with an iat claim value that is
     * unreasonably far in the past
     *
     * @param issuedAtTime        Token issued time
     * @param currentTimeInMillis Current time
     * @param timeStampSkewMillis Time skew
     * @return true or false
     */
    public boolean validateAgeOfTheToken(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis) throws
            IdentityOAuth2Exception {
        if (notAcceptBeforeTimeInMins > 0) {
            long issuedAtTimeMillis = issuedAtTime.getTime();
            long rejectBeforeMillis = 1000L * 60 * notAcceptBeforeTimeInMins;
            if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis >
                    rejectBeforeMillis) {
                return invalidateToken("JSON Web Token is issued before the allowed time." +
                        " Issued At Time(ms) : " + issuedAtTimeMillis +
                        ", Reject before limit(ms) : " + rejectBeforeMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Issued At Time(iat) of JWT was validated successfully.");
        }
        return true;
    }

    /**
     * Method to check whether the JTI is already in the cache.
     *
     * @param jti       JSON Token Id
     * @param signedJWT Signed JWT
     * @param entry     Cache entry
     * @param jwtCache
     * @return true or false
     */
    public boolean validateJTIInCache(String jti, SignedJWT signedJWT, JWTCacheEntry entry, long currentTimeInMillis,
                                      long timeStampSkewMillis, JWTCache jwtCache) throws IdentityOAuth2Exception {
        if (entry == null) {
            // Update the cache with the new JWT for the same JTI.
            jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
            if (log.isDebugEnabled()) {
                log.debug("jti of the JWT has been validated successfully and cache updated.");
            }
        } else if (preventTokenReuse) {
            return invalidateToken("JWT Token \n" + signedJWT.getHeader().toJSONObject().toString() + "\n"
                    + signedJWT.getPayload().toJSONObject().toString() + "\n" +
                    "Has been replayed");
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
                handleException("Unable to parse the cached jwt assertion : " + entry.getEncodedJWt());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT id: " + jti + " not found in the cache and the JWT has been validated " +
                    "successfully in cache.");
        }
        return true;
    }

    /**
     * Check whether the validity period is OK
     * @param jti
     * @param jwtExpiryTimeMillis
     * @param currentTimeInMillis
     * @param timeStampSkewMillis
     * @return
     * @throws IdentityOAuth2Exception
     */
    public boolean checkJTIValidityPeriod(String jti, long jwtExpiryTimeMillis, long currentTimeInMillis,
                                          long timeStampSkewMillis) throws IdentityOAuth2Exception {
        if (currentTimeInMillis + timeStampSkewMillis > jwtExpiryTimeMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JWT Token with jti: " + jti + "has been reused after the allowed expiry time : "
                        + jwtExpiryTimeMillis);
            }
        } else {
            return invalidateToken("JWT Token with jti: " + jti + " Has been replayed before the allowed expiry time : "
                    + jwtExpiryTimeMillis);
        }
        return true;
    }

    /**
     * Method to validate the claims other than
     * iss - Issuer
     * sub - Subject
     * aud - Audience
     * exp - Expiration Time
     * nbf - Not Before
     * iat - Issued At
     * typ - Type
     * <p/>
     * in order to write your own way of validation and use the JWT grant handler,
     * you can extend this class and override this method
     *
     * @param customClaims a map of custom claims
     * @return whether the token is valid based on other claim values
     */
    public boolean validateCustomClaims(Map<String, Object> customClaims) {
        return true;
    }

    public boolean validateJwtInDataBase(String jti, long currentTimeInMillis,
                                         long timeStampSkewMillis) throws IdentityOAuth2Exception {
        JWTEntry jwtEntry = null;
        try {
            jwtEntry = jwtStorageManager.getJwtFromDB(jti);
        } catch (IdentityOAuth2Exception e) {
            handleException("Error while loading jwt with jti: " + jti + " from database");
        }
        if (jwtEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("JWT id: " + jti + " not found in the Storage the JWT has been validated successfully.");
            }
            return true;
        } else if (preventTokenReuse) {
            return invalidateToken("JWT Token with jti: " + jti + " has been replayed");
        } else {
            if (!checkJTIValidityPeriod(jti, jwtEntry.getExp(), currentTimeInMillis, timeStampSkewMillis)) {
                return false;
            }
        }
        return true;
    }

    public void persistJWTID(final String jti, long expiryTime, long issuedTime) {
        jwtStorageManager.persistJwt(jti, expiryTime, issuedTime);
    }

}
