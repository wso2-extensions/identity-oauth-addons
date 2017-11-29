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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axis2.util.JavaUtils;
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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage.PrivateKeyJWTStorageManager;
import org.wso2.carbon.identity.oauth2.token.handlers.clientauth.AbstractClientAuthHandler;
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
import java.util.Properties;

public class PrivateKeyJWTClientAuthHandler extends AbstractClientAuthHandler {

    private static Log log = LogFactory.getLog(PrivateKeyJWTClientAuthHandler.class);

    private String tenantDomain;
    private int rejectBeforePeriod;
    private JWTCache jwtCache;
    private boolean cacheUsedJTI;
    private boolean preventTokenReuse;
    private String validAudience;
    private String subjectField;
    private String validIssuer;
    private String certificateAlias;

    private PrivateKeyJWTStorageManager privateKeyJWTStorageManager;
    protected Properties properties;

    class JWTIDPersistingThread implements Runnable {
        long authenticatedTime;
        String jti;
        long expiryTime;

        public JWTIDPersistingThread(String jti, long expiryTime) {
            super();
            this.expiryTime = expiryTime;
            this.jti = jti;
            this.authenticatedTime = new java.util.Date().getTime();
        }

        @Override
        public void run() {
            try {
                privateKeyJWTStorageManager.persistJWTIdInDB(jti, expiryTime, authenticatedTime);
                if (log.isDebugEnabled()) {
                    log.debug("JWT Token with jti:" + jti + " was added to the storage successfully");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Error occurred while persisting JWT ID:" + jti, e);
            }
        }
    }

    @Override
    public void init(Properties properties) throws IdentityOAuth2Exception {
        this.properties = properties;
        authConfig = properties.getProperty(OAuthConstants.CLIENT_AUTH_CREDENTIAL_VALIDATION);
        privateKeyJWTStorageManager = new PrivateKeyJWTStorageManager();
        try {

            String rejectBeforePeriodConfigVal = properties.getProperty(Constants.VALIDITY_PERIOD);
            if (StringUtils.isNotEmpty(rejectBeforePeriodConfigVal)) {
                rejectBeforePeriod = Integer.parseInt(rejectBeforePeriodConfigVal);
            } else {
                rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD;
            }

            String cacheUsedJTIConfigVal = properties.getProperty(Constants.USE_CACHE_FOR_JTI);
            if (StringUtils.isNotEmpty(cacheUsedJTIConfigVal)) {
                cacheUsedJTI = Boolean.parseBoolean(cacheUsedJTIConfigVal);
            } else {
                cacheUsedJTI = Constants.DEFAULT_USE_CACHE_FOR_JTI_VALUE;
            }

            if (cacheUsedJTI) {
                this.jwtCache = JWTCache.getInstance();
            }

            String validAudienceConfigVal = properties.getProperty(Constants.AUDIENCE);
            if (StringUtils.isNotEmpty(validAudienceConfigVal)) {
                validAudience = validAudienceConfigVal;
            } else {
                validAudience = null;
            }

            String validIssuerConfigVal = properties.getProperty(Constants.ISSUER);
            if (StringUtils.isNotEmpty(validIssuerConfigVal)) {
                validIssuer = validIssuerConfigVal;
            } else {
                validIssuer = null;
            }

            String validSubjectConfigVal = properties.getProperty(Constants.SUBJECT_FIELD);
            if (StringUtils.isNotEmpty(validSubjectConfigVal)) {
                subjectField = validSubjectConfigVal;
            } else {
                subjectField = Constants.CLIENT_ID;
            }

            String certificateAliasConfigVal = properties.getProperty(Constants.SUBJECT_FIELD);
            if (StringUtils.isNotEmpty(validSubjectConfigVal)) {
                certificateAlias = certificateAliasConfigVal;
            } else {
                certificateAlias = null;
            }

            String preventTokenReuseConfigVal = properties.getProperty(Constants.PREVENT_TOKEN_REUSE);
            preventTokenReuse = !StringUtils.isNotEmpty(validSubjectConfigVal) || Boolean.parseBoolean(preventTokenReuseConfigVal);

        } catch (NumberFormatException e) {
            log.warn("Invalid PrivateKeyJWT Validity period found in the configuration. Using default value.");
            rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD;
        }
    }

    @Override
    public boolean canAuthenticate(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String clientAssertionType = getRequestParameter(tokReqMsgCtx, Constants.OAUTH_JWT_ASSERTION_TYPE);
        String clientAssertion = getRequestParameter(tokReqMsgCtx, Constants.OAUTH_JWT_ASSERTION);

        if (StringUtils.isNotEmpty(oAuth2AccessTokenReqDTO.getClientId()) &&
                StringUtils.isNotEmpty(clientAssertionType) && Constants.OAUTH_JWT_BEARER_GRANT_TYPE.equals
                (clientAssertionType) && StringUtils.isNotEmpty(clientAssertion)) {
            if (log.isDebugEnabled()) {
                log.debug("Can authenticate with client ID: " + oAuth2AccessTokenReqDTO.getClientId() + " and " +
                        "private_key_jwt: " + clientAssertion);
            }
            return true;
        } else {
            if (org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString().equals(
                    oAuth2AccessTokenReqDTO.getGrantType())) {

                //Getting configured value for client credential validation requirements
                authConfig = properties.getProperty(OAuthConstants.CLIENT_AUTH_CREDENTIAL_VALIDATION);

                if (log.isDebugEnabled()) {
                    log.debug("Grant type : " + oAuth2AccessTokenReqDTO.getGrantType());
                }

                //If user has set strict validation to false, can authenticate without credentials
                if (StringUtils.isNotEmpty(authConfig) && JavaUtils.isFalseExplicitly(authConfig)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Client auth credential validation set to : " + authConfig + ". " +
                                "can authenticate without client secret");
                    }
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        boolean isAuthenticated = super.authenticateClient(tokReqMsgCtx);

        if (!isAuthenticated) {
            try {
                return authenticateTokenRequest(tokReqMsgCtx);
            } catch (IdentityOAuth2Exception e) {
                return false;
            }
        } else {
            return true;
        }

    }

    private boolean authenticateTokenRequest(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        String tokenEndPointAlias = null;
        ReadOnlyJWTClaimsSet claimsSet;

        signedJWT = getSignedJWT(tokReqMsgCtx);
        if (signedJWT == null) {
            handleException("No Valid Assertion was found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE);
        }
        claimsSet = getClaimSet(signedJWT);
        if (claimsSet == null) {
            handleException("Claim values are empty in the given JSON Web Token.");
        }

        String jwtIssuer = claimsSet.getIssuer();
        String subject = resolveSubject(claimsSet);
        List<String> audience = claimsSet.getAudience();
        Date expirationTime = claimsSet.getExpirationTime();
        Date notBeforeTime = claimsSet.getNotBeforeTime();
        Date issuedAtTime = claimsSet.getIssueTime();
        String jti = claimsSet.getJWTID();
        Map<String, Object> customClaims = claimsSet.getCustomClaims();
        boolean signatureValid;
        boolean audienceFound = false;
        long currentTimeInMillis = System.currentTimeMillis();
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;

        if (StringUtils.isEmpty(jwtIssuer) || StringUtils.isEmpty(subject) || expirationTime == null || audience ==
                null || (preventTokenReuse && jti == null)) {
            handleException("Mandatory fields(Issuer, Subject, Expiration time , " +
                    "JWT ID or Audience) are empty in the given JSON Web Token.");
        }

        if (StringUtils.isNotEmpty(validIssuer) && !validIssuer.equals(jwtIssuer)) {
            handleException("Invalid Issuer:" + jwtIssuer + " in the given" +
                    " JSON Web Token.");
        }

        validateJTI(signedJWT, jti);

        if (Constants.CLIENT_ID.equals(subjectField)) {

            //validate whether the subject is client_id
            OAuthAppDO oAuthAppDO = null;
            try {
                oAuthAppDO = OAuth2Util.getAppInformationByClientId(subject);
            } catch (InvalidOAuthClientException e) {
                handleException("Error while retrieving OAuth application with provided JWT information.");
            }

            if (oAuthAppDO == null) {
                handleException("Unable to find OAuth application with provided JWT information.");
            }

            if (StringUtils.isEmpty(validIssuer) && !jwtIssuer.equals(subject)) {
                handleException("Invalid field Issuer:" + jwtIssuer + " in the given JSON Web Token.");
            }

            tenantDomain = oAuthAppDO.getUser().getTenantDomain();
        }

        //validate signature
        String alias = subject;
        if (StringUtils.isNotEmpty(certificateAlias)) {
            alias = certificateAlias;
        }
        try {

            X509Certificate cert = getCertificate(tenantDomain, alias);
            signatureValid = validateSignature(signedJWT, cert);
            if (signatureValid) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature/MAC validated successfully.");
                }
            } else {
                handleException("Signature or Message Authentication invalid.");
            }
        } catch (JOSEException e) {
            handleException("Error when verifying signature.");
        }
        if (log.isDebugEnabled()) {
            log.debug("Issuer(iss) of the JWT validated successfully. ");
        }

        //validate audience
        tokenEndPointAlias = getTokenEndpointAlias();
        audienceFound = validateAudience(tokenEndPointAlias, audience);
        if (!audienceFound) {
            handleException("None of the audience values matched the tokenEndpoint Alias " + tokenEndPointAlias);
        }

        //Check token Expiry
        boolean checkedExpirationTime = checkExpirationTime(expirationTime, currentTimeInMillis,
                timeStampSkewMillis);
        if (checkedExpirationTime) {
            if (log.isDebugEnabled()) {
                log.debug("Expiration Time(exp) of JWT was validated successfully.");
            }
        }
        //check notbefore time
        if (notBeforeTime == null) {
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) not found in JWT. Continuing Validation");
            }
        } else {
            boolean checkedNotBeforeTime = checkNotBeforeTime(notBeforeTime, currentTimeInMillis,
                    timeStampSkewMillis);
            if (checkedNotBeforeTime) {
                if (log.isDebugEnabled()) {
                    log.debug("Not Before Time(nbf) of JWT was validated successfully.");
                }
            }
        }

        //check issued time
        if (issuedAtTime == null) {
            if (log.isDebugEnabled()) {
                log.debug("Issued At Time(iat) not found in JWT. Continuing Validation");
            }
        } else {
            boolean checkedValidityToken = checkValidityOfTheToken(issuedAtTime, currentTimeInMillis,
                    timeStampSkewMillis);
            if (checkedValidityToken) {
                if (log.isDebugEnabled()) {
                    log.debug("Issued At Time(iat) of JWT was validated successfully.");
                }
            }
        }

        // validate custom claims
        if (customClaims == null) {
            if (log.isDebugEnabled()) {
                log.debug("No custom claims found. Continue validating other claims.");
            }
        } else {
            boolean customClaimsValidated = validateCustomClaims(claimsSet.getCustomClaims());
            if (!customClaimsValidated) {
                handleException("Custom Claims in the JWT were invalid");
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT Token was validated successfully");
        }
        if (cacheUsedJTI) {
            jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT Token was added to the cache successfully");
        }

        persistJWTID(jti, expirationTime.getTime());
        return true;
    }

    private void validateJTI(SignedJWT signedJWT, String jti) throws IdentityOAuth2Exception {
        //check whether the token is already used
        //check JWT ID in cache
        //TODO
        if (cacheUsedJTI && (jti != null)) {
            JWTCacheEntry entry = (JWTCacheEntry) jwtCache.getValueFromCache(jti);
            if (checkCachedJTI(jti, signedJWT, entry)) {
                if (log.isDebugEnabled()) {
                    log.debug("JWT id: " + jti + " not found in the cache and the JWT has been validated " +
                            "successfully in cache.");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                if (!cacheUsedJTI) {
                    log.debug("List of used JSON Web Token IDs are not maintained in cache. Continue Validation");
                }
            }
        }

        // check JWT ID in DB
        if (checkJWTIDinDataBase(jti)) {
            if (log.isDebugEnabled()) {
                log.debug("JWT id: " + jti + " not found in the Storage the JWT has been validated successfully.");
            }
        } else {
            handleException("JWT with jti: " + jti + " is already used for authentication.");
        }
    }

    private boolean validateAudience(String tokenEndPointAlias, List<String> audience) {
        for (String aud : audience) {
            if (StringUtils.equals(tokenEndPointAlias, aud)) {
                if (log.isDebugEnabled()) {
                    log.debug(tokenEndPointAlias + " is found in the list of audiences.");
                }
                return true;
            }
        }
        return false;
    }

    private String getTokenEndpointAlias() throws IdentityOAuth2Exception {
        if (StringUtils.isNotEmpty(validAudience)) {
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

        if (StringUtils.isEmpty(tokenEndPointAlias)) {
            tokenEndPointAlias = IdentityUtil.getServerURL(IdentityConstants.OAuth.TOKEN, true, false);
        }
        return tokenEndPointAlias;
    }

    /**
     * @param tokReqMsgCtx Token message request context
     * @return signedJWT
     */
    private SignedJWT getSignedJWT(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String assertion = null;
        SignedJWT signedJWT = null;
        for (RequestParameter param : params) {
            if (param.getKey().equals(Constants.OAUTH_JWT_ASSERTION)) {
                assertion = param.getValue()[0];
                break;
            }
        }
        if (StringUtils.isEmpty(assertion)) {
            return null;
        }

        try {
            signedJWT = SignedJWT.parse(assertion);
            if (log.isDebugEnabled()) {
                logJWT(signedJWT);
            }
        } catch (ParseException e) {
            handleException("Error while parsing the JWT" + e.getMessage());
        }
        return signedJWT;
    }

    /**
     * @param tokReqMsgCtx Token message request context
     * @return parameter
     */
    private String getRequestParameter(OAuthTokenReqMessageContext tokReqMsgCtx,
                                       String paramName) throws IdentityOAuth2Exception {
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String paramVal = null;
        for (RequestParameter param : params) {
            if (param.getKey().equals(paramName)) {
                paramVal = param.getValue()[0];
                break;
            }
        }
        if (StringUtils.isEmpty(paramVal)) {
            return null;
        }
        return paramVal;
    }

    /**
     * @param signedJWT the signedJWT to be logged
     */
    private void logJWT(SignedJWT signedJWT) {
        log.debug("JWT Header: " + signedJWT.getHeader().toJSONObject().toString());
        log.debug("JWT Payload: " + signedJWT.getPayload().toJSONObject().toString());
        log.debug("Signature: " + signedJWT.getSignature().toString());
    }

    private void handleException(String errorMessage) throws IdentityOAuth2Exception {
        log.error(errorMessage);
        throw new IdentityOAuth2Exception(errorMessage);
    }


    /**
     * @param signedJWT Signed JWT
     * @return Claim set
     */
    private ReadOnlyJWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {
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
    private String resolveSubject(ReadOnlyJWTClaimsSet claimsSet) {
        return claimsSet.getSubject();
    }


    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param tenantDomain tenant domain of the issuer
     * @param alias        alias of cert
     * @return X509CredentialImpl object containing the public certificate of that tenant
     */
    protected static X509Certificate getCertificate(String tenantDomain, String alias) throws IdentityOAuth2Exception {

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
            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
            return cert;

        } catch (KeyStoreException e) {
            String errorMsg = "Error instantiating an X509CredentialImpl object for the public certificate of "
                    + tenantDomain;
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
    private static String generateKSNameFromDomainName(String tenantDomain) {
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
    private boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate)
            throws JOSEException, IdentityOAuth2Exception {

        JWSVerifier verifier = null;
        ReadOnlyJWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            handleException("Unable to locate certificate for JWT " + header.toString());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            handleException("Algorithm must not be null.");
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
                    handleException("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet : " + alg);
                }
            }
            if (verifier == null) {
                handleException("Could not create a signature verifier for algorithm type: " + alg);
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
    private boolean checkExpirationTime(Date expirationTime, long currentTimeInMillis, long timeStampSkewMillis) throws IdentityOAuth2Exception {
        long expirationTimeInMillis = expirationTime.getTime();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            handleException("JSON Web Token is expired." +
                    " Expiration Time(ms) : " + expirationTimeInMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
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
    private boolean checkNotBeforeTime(Date notBeforeTime, long currentTimeInMillis, long timeStampSkewMillis) throws IdentityOAuth2Exception {
        long notBeforeTimeMillis = notBeforeTime.getTime();
        if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
            handleException("JSON Web Token is used before Not_Before_Time." +
                    " Not Before Time(ms) : " + notBeforeTimeMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
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
    private boolean checkValidityOfTheToken(Date issuedAtTime, long currentTimeInMillis, long timeStampSkewMillis) throws IdentityOAuth2Exception {
        long issuedAtTimeMillis = issuedAtTime.getTime();
        long rejectBeforeMillis = 1000L * 60 * rejectBeforePeriod;
        if (currentTimeInMillis + timeStampSkewMillis - issuedAtTimeMillis >
                rejectBeforeMillis) {
            handleException("JSON Web Token is issued before the allowed time." +
                    " Issued At Time(ms) : " + issuedAtTimeMillis +
                    ", Reject before limit(ms) : " + rejectBeforeMillis +
                    ", TimeStamp Skew : " + timeStampSkewMillis +
                    ", Current Time : " + currentTimeInMillis + ". JWT Rejected and validation terminated");
        }
        return true;
    }

    /**
     * Method to check whether the JTI is already in the cache.
     *
     * @param jti       JSON Token Id
     * @param signedJWT Signed JWT
     * @param entry     Cache entry
     * @return true or false
     */
    private boolean checkCachedJTI(String jti, SignedJWT signedJWT, JWTCacheEntry entry) throws IdentityOAuth2Exception {
        if (entry == null) {
            // Update the cache with the new JWT for the same JTI.
            this.jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
            if (log.isDebugEnabled()) {
                log.debug("jti of the JWT has been validated successfully and cache updated.");
            }
        } else {
            handleException("JWT Token \n" + signedJWT.getHeader().toJSONObject().toString() + "\n"
                    + signedJWT.getPayload().toJSONObject().toString() + "\n" +
                    "Has been replayed");
        }
        return true;
    }

//    private boolean checkCachedJTI(String jti, SignedJWT signedJWT, JWTCacheEntry entry, long currentTimeInMillis,
//                                   long timeStampSkewMillis) throws IdentityOAuth2Exception {
//        try {
//            SignedJWT cachedJWT = entry.getJwt();
//            long cachedJWTExpiryTimeMillis = cachedJWT.getJWTClaimsSet().getExpirationTime().getTime();
//            if (currentTimeInMillis + timeStampSkewMillis > cachedJWTExpiryTimeMillis) {
//                if (log.isDebugEnabled()) {
//                    log.debug("JWT Token has been reused after the allowed expiry time : "
//                            + cachedJWT.getJWTClaimsSet().getExpirationTime());
//                }
//
//                // Update the cache with the new JWT for the same JTI.
//                this.jwtCache.addToCache(jti, new JWTCacheEntry(signedJWT));
//                if (log.isDebugEnabled()) {
//                    log.debug("jti of the JWT has been validated successfully and cache updated");
//                }
//            } else {
//                handleException("JWT Token \n" + signedJWT.getHeader().toJSONObject().toString() + "\n"
//                        + signedJWT.getPayload().toJSONObject().toString() + "\n" +
//                        "Has been replayed before the allowed expiry time : "
//                        + cachedJWT.getJWTClaimsSet().getExpirationTime());
//            }
//        } catch (ParseException e) {
//            handleException("Unable to parse the cached jwt assertion : " + entry.getEncodedJWt());
//        }
//        return true;
//    }

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
    protected boolean validateCustomClaims(Map<String, Object> customClaims) {
        return true;
    }

    private boolean checkJWTIDinDataBase(String jti) throws IdentityOAuth2Exception {
        try {
            return !privateKeyJWTStorageManager.isJTIExistsInDB(jti);
        } catch (IdentityOAuth2Exception e) {
            log.error(e.getMessage(), e);
        }
        return true;
    }

    private void persistJWTID(final String jti, long expiryTime) {
        new Thread(new JWTIDPersistingThread(jti, expiryTime)).start();
    }
}