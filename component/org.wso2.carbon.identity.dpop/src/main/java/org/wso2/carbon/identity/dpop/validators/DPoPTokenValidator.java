package org.wso2.carbon.identity.dpop.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

/**
 * DPoP token validator.
 */
public class DPoPTokenValidator implements OAuth2TokenValidator {

    private static final String ALGO_PREFIX = "RS";
    private static final String DOT_SEPARATOR = ".";
    private static final Log log = LogFactory.getLog(DPoPTokenValidator.class);
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";

    @Override
    public boolean validateAccessDelegation(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        return true;
    }

    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        return true;
    }

    @Override
    public boolean validateAccessToken(OAuth2TokenValidationMessageContext validationReqDTO) throws IdentityOAuth2Exception {

        if (!isJWT(validationReqDTO.getRequestDTO().getAccessToken().getIdentifier())) {
            return true;
        }

        try {
            SignedJWT signedJWT = getSignedJWT(validationReqDTO);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
            }

            validateRequiredFields(claimsSet);
            IdentityProvider identityProvider = getResidentIDPForIssuer(claimsSet.getIssuer());

            if (!validateSignature(signedJWT, identityProvider)) {
                return false;
            }
            if (!checkExpirationTime(claimsSet.getExpirationTime())) {
                return false;
            }
            checkNotBeforeTime(claimsSet.getNotBeforeTime());
        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
        return true;
    }

    @Override
    public String getTokenType() {

        return "DPoP";
    }

    private SignedJWT getSignedJWT(OAuth2TokenValidationMessageContext validationReqDTO) throws ParseException {

        return SignedJWT.parse(validationReqDTO.getRequestDTO().getAccessToken().getIdentifier());
    }

    private boolean validateRequiredFields(JWTClaimsSet claimsSet) throws IdentityOAuth2Exception {

        String subject = resolveSubject(claimsSet);
        List<String> audience = claimsSet.getAudience();

        if (StringUtils.isBlank(String.valueOf(claimsSet.getClaims().containsKey(DPoPConstants.CNF)))
                && StringUtils.isBlank(claimsSet.getClaim(DPoPConstants.CNF).toString())) {
            throw new IdentityOAuth2Exception("Mandatory field cnf is  empty in the given Token.");
        }

        String jti = claimsSet.getJWTID();
        if (StringUtils.isEmpty(claimsSet.getIssuer()) || StringUtils.isEmpty(subject) ||
                claimsSet.getExpirationTime() == null || audience == null || jti == null) {
            throw new IdentityOAuth2Exception("Mandatory fields(Issuer, Subject, Expiration time," +
                    " jtl or Audience) are empty in the given Token.");
        }
        return true;
    }

    private String resolveSubject(JWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    /**
     * The default implementation resolves one certificate to Identity Provider and ignores the JWT header.
     * Override this method, to resolve and enforce the certificate in any other way
     * such as x5t attribute of the header.
     *
     * @param header The JWT header. Some of the x attributes may provide certificate information.
     * @param idp    The identity provider, if you need it.
     * @return the resolved X509 Certificate, to be used to validate the JWT signature.
     * @throws IdentityOAuth2Exception something goes wrong.
     */
    protected X509Certificate resolveSignerCertificate(JWSHeader header,
                                                       IdentityProvider idp) throws IdentityOAuth2Exception {

        X509Certificate x509Certificate;
        String tenantDomain = getTenantDomain();
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception("Error occurred while decoding public certificate of Identity Provider "
                    + idp.getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }
        return x509Certificate;
    }

    private IdentityProvider getResidentIDPForIssuer(String jwtIssuer) throws IdentityOAuth2Exception {

        String tenantDomain = getTenantDomain();
        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg =
                    String.format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDC_IDP_ENTITY_ID).getValue();
        }

        if (!jwtIssuer.equals(issuer)) {
            throw new IdentityOAuth2Exception("No Registered IDP found for the token with issuer name : " + jwtIssuer);
        }
        return residentIdentityProvider;
    }

    private boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception {

        JWSVerifier verifier = null;
        JWSHeader header = signedJWT.getHeader();
        X509Certificate x509Certificate = resolveSignerCertificate(header, idp);
        if (x509Certificate == null) {
            throw new IdentityOAuth2Exception("Unable to locate certificate for Identity Provider: " + idp
                    .getDisplayName());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new IdentityOAuth2Exception("Algorithm must not be null.");

        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the Token Header: " + alg);
            }
            if (alg.indexOf(ALGO_PREFIX) == 0) {
                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new IdentityOAuth2Exception("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet: " + alg);
                }
            }
            if (verifier == null) {
                throw new IdentityOAuth2Exception("Could not create a signature verifier for algorithm type: " + alg);
            }
        }

        boolean isValid = signedJWT.verify(verifier);
        if (log.isDebugEnabled()) {
            log.debug("Signature verified: " + isValid);
        }
        return isValid;
    }

    private boolean checkExpirationTime(Date expirationTime) {

        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();
        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug("Token is expired." +
                        ", Expiration Time(ms) : " + expirationTimeInMillis +
                        ", TimeStamp Skew : " + timeStampSkewMillis +
                        ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
            }
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Expiration Time(exp) of Token was validated successfully.");
        }
        return true;
    }

    private boolean checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Token is used before Not_Before_Time." +
                            ", Not Before Time(ms) : " + notBeforeTimeMillis +
                            ", TimeStamp Skew : " + timeStampSkewMillis +
                            ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }
        return true;
    }

    private String getTenantDomain() {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    /**
     * Return true if the token identifier is JWT.
     *
     * @param tokenIdentifier String JWT token identifier.
     * @return true for a JWT token.
     */
    private boolean isJWT(String tokenIdentifier) {
        // JWT token contains 3 base64 encoded components separated by periods.
        return StringUtils.countMatches(tokenIdentifier, DOT_SEPARATOR) == 2;
    }
}
