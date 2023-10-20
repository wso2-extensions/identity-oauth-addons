/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.cache.JWTCacheKey;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceServerException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.dao.JWTStorageManager;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceComponent;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util.Util;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * This class is used to validate the JWT which is coming along with the request.
 */
public class JWTValidator {

    private static final Log log = LogFactory.getLog(JWTValidator.class);
    public static final String FULLSTOP_DELIMITER = ".";
    public static final String DASH_DELIMITER = "-";
    public static final String KEYSTORE_FILE_EXTENSION = ".jks";
    public static final String RS = "RS";
    public static final String PS = "PS";
    private static final String IDP_ENTITY_ID = "IdPEntityId";
    private static final String PROP_ID_TOKEN_ISSUER_ID = "OAuth.OpenIDConnect.IDTokenIssuerID";
    private static final String FAPI_SIGNATURE_ALG_CONFIGURATION = "OAuth.OpenIDConnect.FAPI." +
            "AllowedSignatureAlgorithms.AllowedSignatureAlgorithm";
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
     * @throws OAuthClientAuthnException OAuthClientAuthnException thrown with Invalid Request error code.
     */
    public boolean isValidAssertion(SignedJWT signedJWT) throws OAuthClientAuthnException {

        String errorMessage;

        if (signedJWT == null) {
            errorMessage = "No valid JWT assertion found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
            return logAndThrowException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        try {
            JWTClaimsSet claimsSet = getClaimSet(signedJWT);

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
            int tenantId = JWTServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            if (!validateMandatoryFeilds(mandatoryClaims, claimsSet)) {
                return false;
            }

            //Validate issuer and subject.
            if (!validateIssuer(jwtIssuer, consumerKey) || !validateSubject(jwtSubject, consumerKey)) {
                return false;
            }

            /* A list of valid audiences (issuer identifier, token endpoint URL or pushed authorization request
            endpoint URL) should be supported for PAR and not just a single valid audience.
            https://datatracker.ietf.org/doc/html/rfc9126 */
            List<String> acceptedAudienceList = getValidAudiences(tenantDomain);

            long expTime = 0;
            long issuedTime = 0;
            if (expirationTime != null) {
                expTime = expirationTime.getTime();
            }
            if (issuedAtTime != null) {
                issuedTime = issuedAtTime.getTime();
            }

            //   Obtain the signing algorithm used to sign the JWT in the request.
            String requestSigningAlgorithm = signedJWT.getHeader().getAlgorithm().getName();
            if (!isValidSignatureAlgorithm(requestSigningAlgorithm, consumerKey)) {
                throw new OAuthClientAuthnException("Signature algorithm used in the request is invalid.",
                        OAuth2ErrorCodes.INVALID_CLIENT);
            }

            /* Check whether the request signing algorithm is an allowed algorithm as per the FAPI specification.
               https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations */
            try {
                if (OAuth2Util.isFapiConformantApp(consumerKey)) {
                    //   Mandating FAPI specified JWT signing algorithms.
                    List<String> fapiAllowedSigningAlgorithms = IdentityUtil
                            .getPropertyAsList(FAPI_SIGNATURE_ALG_CONFIGURATION);
                    if (!fapiAllowedSigningAlgorithms.contains(requestSigningAlgorithm)) {
                        throw new OAuthClientAuthnException("FAPI unsupported signing algorithm " + requestSigningAlgorithm
                                + " is used to sign the JWT.", OAuth2ErrorCodes.INVALID_CLIENT);
                    }
                }
            } catch (IdentityOAuth2ClientException e) {
                throw new OAuthClientAuthnException("Could not find an existing app for clientId: " + consumerKey,
                        OAuth2ErrorCodes.INVALID_CLIENT);
            } catch (IdentityOAuth2Exception e) {
                throw new OAuthClientAuthnException("Error while obtaining the service provider for client_id: " +
                        consumerKey, OAuth2ErrorCodes.SERVER_ERROR);
            }

            preventTokenReuse = !JWTServiceDataHolder.getInstance()
                    .getPrivateKeyJWTAuthenticationConfigurationDAO()
                    .getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(tenantDomain).isEnableTokenReuse();

            //Validate signature validation, audience, nbf,exp time, jti.
            if (!validateAudience(acceptedAudienceList, audience)
                    || !validateJWTWithExpTime(expirationTime, currentTimeInMillis, timeStampSkewMillis)
                    || !validateNotBeforeClaim(currentTimeInMillis, timeStampSkewMillis, nbf)
                    || !validateAgeOfTheToken(issuedAtTime, currentTimeInMillis, timeStampSkewMillis)
                    || !isValidSignature(consumerKey, signedJWT, tenantDomain, jwtSubject, tenantId)
                    || !validateJTI(signedJWT, jti, currentTimeInMillis, timeStampSkewMillis, expTime,
                    issuedTime, tenantId)) {
                return false;
            }

            return true;

        } catch (IdentityOAuth2Exception e) {
            return logAndThrowException(e.getMessage(), e.getErrorCode());
        } catch (UserStoreException | JWTClientAuthenticatorServiceServerException e) {
            return logAndThrowException(e.getMessage(), OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private boolean validateMandatoryFeilds(List<String> mandatoryClaims, JWTClaimsSet claimsSet) throws OAuthClientAuthnException {

        for (String mandatoryClaim : mandatoryClaims) {
            if (claimsSet.getClaim(mandatoryClaim) == null) {
                String errorMessage = "Mandatory field :" + mandatoryClaim + " is missing in the JWT assertion.";
                return logAndThrowException(errorMessage, OAuth2ErrorCodes.INVALID_REQUEST);
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

    // The valid audience value should either be the issuer identifier or the token endpoint URL or the pushed authorization
    // request endpoint URL
    private boolean validateAudience(List<String> expectedAudiences, List<String> audience) throws OAuthClientAuthnException {

        for (String aud : audience) {
            if (expectedAudiences.contains(aud)) {
                return true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("None of the audience values : " + audience + " matched the expected audiences : " + expectedAudiences);
        }
        throw new OAuthClientAuthnException("Failed to match audience values.", OAuth2ErrorCodes.INVALID_REQUEST);
    }

    // "REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens
    // MUST only be used once, unless conditions for reuse were negotiated between the parties; any such negotiation is
    // beyond the scope of this specification."
    private boolean validateJTI(SignedJWT signedJWT, String jti, long currentTimeInMillis,
                                long timeStampSkewMillis, long expTime, long issuedTime, int tenantId)
            throws OAuthClientAuthnException {

        if (enableJTICache) {
            JWTCacheKey jwtCacheKey;
            if (Util.isTenantIdColumnAvailableInIdnOidcAuth()) {
                jwtCacheKey = new JWTCacheKey(jti, tenantId);
            } else {
                jwtCacheKey = new JWTCacheKey(jti);
            }
            JWTCacheEntry entry = jwtCache.getValueFromCache(jwtCacheKey);
            if (!validateJTIInCache(jti, signedJWT, entry, currentTimeInMillis, timeStampSkewMillis, this.jwtCache,
                    tenantId)) {
                return false;
            }
        }
        // Check JWT ID in DB
        if (!validateJWTInDataBase(jti, currentTimeInMillis, timeStampSkewMillis, tenantId)) {
            return false;
        }
        persistJWTID(jti, expTime, issuedTime, tenantId);
        return true;
    }

    private boolean validateJWTInDataBase(String jti, long currentTimeInMillis,
                                          long timeStampSkewMillis, int tenantId) throws OAuthClientAuthnException {

        JWTEntry jwtEntry = getJTIfromDB(jti, tenantId);
        if (jwtEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("JWT id: " + jti + " not found in the Storage the JWT has been validated successfully.");
            }
            return true;
        } else if (preventTokenReuse) {
            String message = "JWT Token with JTI: " + jti + " has been replayed.";
            return logAndThrowException(message, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        // Token reuse is allowed. Here we are logging whether the token is reused within the allowed expiry time.
        if (currentTimeInMillis + timeStampSkewMillis < jwtEntry.getExp()) {
            if (log.isDebugEnabled()) {
                log.debug("JWT Token with jti: " + jti + "has been reused with in the allowed expiry time: " +
                        jwtEntry.getExp());
            }
        }
        return true;
    }

    /**
     * This method is to get JTI from the DB.
     * For the migration purposes (preserve existing behaviour),
     * We are searching for the current tenant and default tenant.
     *
     * @param jti      JTI.
     * @param tenantId Tenant id.
     * @return JWT entry if exists.
     * @throws OAuthClientAuthnException OAuthClientAuthnException.
     */
    private JWTEntry getJTIfromDB(String jti, final int tenantId) throws OAuthClientAuthnException {

        List<JWTEntry> jwtEntries = jwtStorageManager.getJwtsFromDB(jti, tenantId);

        if (jwtEntries.isEmpty()) {
            return null;
        }
        // If there is only one entry return it.
        if (jwtEntries.size() == 1) {
            return jwtEntries.get(0);
        }
        return jwtEntries.stream().filter(e -> e.getTenantId() == tenantId).findFirst().orElse(null);
    }

    private void persistJWTID(final String jti, long expiryTime, long issuedTime, int tenantId)
            throws OAuthClientAuthnException {

        jwtStorageManager.persistJWTIdInDB(jti, tenantId, expiryTime, issuedTime, this.preventTokenReuse);
    }

    private OAuthAppDO getOAuthAppDO(String jwtSubject) throws OAuthClientAuthnException {

        OAuthAppDO oAuthAppDO = null;
        String message = String.format("Error while retrieving OAuth application with provided JWT information with " +
                "subject '%s' ", jwtSubject);
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(jwtSubject);
            if (oAuthAppDO == null) {
                logAndThrowException(message, OAuth2ErrorCodes.INVALID_REQUEST);
            }
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            logAndThrowException(message, OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return oAuthAppDO;
    }

    private boolean logAndThrowException(String detailedMessage, String errorCode) throws OAuthClientAuthnException {

        if (log.isDebugEnabled()) {
            log.debug(detailedMessage);
        }
        throw new OAuthClientAuthnException(detailedMessage, errorCode);
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
                String message = "The token is used before the nbf claim value.";
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw new OAuthClientAuthnException(message, OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        return true;
    }

    private boolean isValidSignature(String clientId, SignedJWT signedJWT, String tenantDomain,
                                     String alias, int tenantId) throws OAuthClientAuthnException {

        X509Certificate cert = null;
        String jwksUri = "";
        boolean isValidSignature = false;
        try {
            cert = (X509Certificate) OAuth2Util.getX509CertOfOAuthApp(clientId, tenantDomain);
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                String message = "Unable to retrieve the certificate for the service provider";
                log.debug(message, e);
            }
        }
        // If cert is null check whether a jwks endpoint is configured for the service provider.
        if (cert == null) {
            try {
                ServiceProviderProperty[] spProperties = OAuth2Util.getServiceProvider(clientId).getSpProperties();
                for (ServiceProviderProperty spProperty : spProperties) {
                    if (Constants.JWKS_URI.equals(spProperty.getName())) {
                        jwksUri = spProperty.getValue();
                        break;
                    }
                }
                // Validate the signature of the assertion using the jwks end point.
                if (StringUtils.isNotBlank(jwksUri)) {
                    if (log.isDebugEnabled()) {
                        String message = "Found jwks end point for service provider " + jwksUri;
                        log.debug(message);
                    }
                    String jwtString = signedJWT.getParsedString();
                    String alg = signedJWT.getHeader().getAlgorithm().getName();
                    Map<String, Object> options = new HashMap<String, Object>();
                    isValidSignature = new JWKSBasedJWTValidator().validateSignature(jwtString, jwksUri, alg, options);
                }
            } catch (IdentityOAuth2Exception e) {
                String errorMessage = "Error occurred while validating signature using jwks ";
                log.error(errorMessage, e);
                return false;
            }
        }
        // If certificate is not configured in service provider, it will throw an error.
        // For the existing clients need to handle that error and get from truststore.
        if (StringUtils.isBlank(jwksUri) && cert == null) {
            cert = getCertificate(tenantDomain, alias, tenantId);
        }
        if (StringUtils.isBlank(jwksUri) && cert != null) {
            try {
                isValidSignature = validateSignature(signedJWT, cert);
            } catch (JOSEException e) {
                String message = "Error while validating the signature";
                throw new OAuthClientAuthnException(message, OAuth2ErrorCodes.INVALID_REQUEST, e);
            }
        }
        return isValidSignature;
    }

    private List<String> getValidAudiences(String tenantDomain) throws OAuthClientAuthnException {

        List<String> validAudiences = new ArrayList<>();
        String tokenEndpoint = null;
        String parEndpoint = null;
        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance()
                    .getResidentIdP(tenantDomain);
            FederatedAuthenticatorConfig oidcFedAuthn = IdentityApplicationManagementUtil
                    .getFederatedAuthenticator(residentIdP.getFederatedAuthenticatorConfigs(),
                            IdentityApplicationConstants.Authenticator.OIDC.NAME);
            Property idpEntityId = IdentityApplicationManagementUtil.getProperty(oidcFedAuthn.getProperties(),
                    IDP_ENTITY_ID);
            Property parEndpointFromResidentIdp = IdentityApplicationManagementUtil.getProperty(oidcFedAuthn
                    .getProperties(), Constants.OAUTH2_PAR_URL_REF);
            if (idpEntityId != null) {
                tokenEndpoint = idpEntityId.getValue();
            }
            if (parEndpointFromResidentIdp != null) {
                parEndpoint = parEndpointFromResidentIdp.getValue();
            }
        } catch (IdentityProviderManagementException e) {
            String message = "Error while loading OAuth2TokenEPUrl and ParEPUrl of the resident IDP of tenant: "
                    + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new OAuthClientAuthnException(message, OAuth2ErrorCodes.INVALID_REQUEST);
        }

        if (StringUtils.isEmpty(tokenEndpoint)) {
            tokenEndpoint = IdentityUtil.getProperty(PROP_ID_TOKEN_ISSUER_ID);
        }
        if (StringUtils.isEmpty(parEndpoint)) {
            parEndpoint = IdentityUtil.getProperty(Constants.OAUTH2_PAR_URL_CONFIG);
        }

        if (StringUtils.isNotEmpty(validAudience)) {
            validAudiences.add(validAudience);
        }
        validAudiences.add(tokenEndpoint);
        validAudiences.add(parEndpoint);
        return validAudiences;
    }

    /**
     * To retreive the processed JWT claimset.
     *
     * @param signedJWT signedJWT
     * @return JWT claim set
     * @throws OAuthClientAuthnException OAuthClientAuthnException thrown with Invalid Request error code.
     */
    public JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws OAuthClientAuthnException {

        JWTClaimsSet claimsSet;
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
    public String resolveSubject(JWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    private static X509Certificate getCertificate(String tenantDomain, String alias, int tenantId)
            throws OAuthClientAuthnException {

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
        JWSHeader header = signedJWT.getHeader();
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
            if (alg.indexOf(RS) == 0 || alg.indexOf(PS) == 0) {
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
                                       long timeStampSkewMillis, JWTCache jwtCache, int tenantId)
            throws OAuthClientAuthnException {

        if (entry == null) {
            // Update the cache with the new JWT for the same JTI.
            JWTCacheKey jwtCacheKey;
            if (Util.isTenantIdColumnAvailableInIdnOidcAuth()) {
                jwtCacheKey = new JWTCacheKey(jti, tenantId);
            } else {
                jwtCacheKey = new JWTCacheKey(jti);
            }
            jwtCache.addToCache(jwtCacheKey, new JWTCacheEntry(signedJWT));
        } else if (preventTokenReuse) {
            throw new OAuthClientAuthnException("JWT Token with jti: " + jti + " has been replayed",
                    OAuth2ErrorCodes.INVALID_REQUEST);
        } else {
            try {
                SignedJWT cachedJWT = entry.getJwt();
                long cachedJWTExpiryTimeMillis = cachedJWT.getJWTClaimsSet().getExpirationTime().getTime();
                // Token reuse is allowed. Here we are logging whether the token is reused within the allowed expiry time.
                if (currentTimeInMillis + timeStampSkewMillis < cachedJWTExpiryTimeMillis) {
                    if (log.isDebugEnabled()) {
                        log.debug("JWT Token with jti: " + jti + "has been reused with in the allowed expiry time: " +
                                cachedJWTExpiryTimeMillis);
                    }
                }
                // Update the cache with the new JWT for the same JTI.
                JWTCacheKey jwtCacheKey;
                if (Util.isTenantIdColumnAvailableInIdnOidcAuth()) {
                    jwtCacheKey = new JWTCacheKey(jti, tenantId);
                } else {
                    jwtCacheKey = new JWTCacheKey(jti);
                }
                jwtCache.addToCache(jwtCacheKey, new JWTCacheEntry(signedJWT));
            } catch (ParseException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to parse the cached jwt assertion : " + entry.getEncodedJWt());
                }
                throw new OAuthClientAuthnException("JTI validation failed.", OAuth2ErrorCodes.INVALID_REQUEST);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("JWT id: " + jti + " for tenant id: " + tenantId + " not found in the cache " +
                    "and the JWT has been validated successfully in cache.");
        }
        return true;
    }

    /**
     * Validate whether the request signing algorithm is configured for the application.
     *
     * @param requestSigningAlgorithm     The request signed algorithm.
     * @param clientId                    Client ID of the application.
     * @return whether the request signing algorithm is configured for the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    private boolean isValidSignatureAlgorithm(String requestSigningAlgorithm, String clientId)
            throws OAuthClientAuthnException {

        //   Obtain the signing algorithm configured for the application.
        List<String> configuredSigningAlgorithms = getConfiguredSigningAlgorithm(clientId);
        //  Validate whether the JWT signing algorithm is configured for the application.
        if (configuredSigningAlgorithms.isEmpty() || configuredSigningAlgorithms.contains(requestSigningAlgorithm)) {
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("JWT signed algorithm: " + requestSigningAlgorithm + " does not match with the configured algorithms: " +
                        configuredSigningAlgorithms);
            }
            return false;
        }
    }

    /**
     * Obtain the request signing algorithms configured for the application.
     *
     * @param clientId   Client ID of the application.
     * @throws OAuthClientAuthnException OAuth Client Authentication Exception.
     */
    private List<String> getConfiguredSigningAlgorithm(String clientId) throws OAuthClientAuthnException {

        List<String> configuredSigningAlgorithms = new ArrayList<>();
        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
            String tokenEndpointAuthSignatureAlgorithm = oAuthAppDO.getTokenEndpointAuthSignatureAlgorithm();
            if (StringUtils.isNotBlank(tokenEndpointAuthSignatureAlgorithm)) {
                configuredSigningAlgorithms = Arrays.asList(tokenEndpointAuthSignatureAlgorithm);
            }
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new OAuthClientAuthnException("Error occurred while retrieving app information for client id: " +
                    clientId + " of tenantDomain: " + tenantDomain, OAuth2ErrorCodes.INVALID_REQUEST, e);
        }
        return configuredSigningAlgorithms;
    }

}
