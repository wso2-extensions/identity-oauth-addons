/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.dpop.listener;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.binding.DPoPBasedTokenBinder;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.constant.OAuthTokenType;
import org.wso2.carbon.identity.dpop.dao.TokenBindingTypeManagerDao;
import org.wso2.carbon.identity.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.oauth.common.DPoPState;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.TokenType;

import javax.servlet.http.HttpServletRequestWrapper;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

/**
 * This class extends {@link AbstractOAuthEventInterceptor} and listen to oauth token related events.
 * In this class, DPoP proof validation will be handled for DPoP token requests.
 */
public class OauthDPoPInterceptorHandlerProxy extends AbstractOAuthEventInterceptor {

    private static final Log log = LogFactory.getLog(OauthDPoPInterceptorHandlerProxy.class);
    private TokenBindingTypeManagerDao
            tokenBindingTypeManagerDao = DPoPDataHolder.getInstance().getTokenBindingTypeManagerDao();

    /**
     * {@inheritdoc}
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception If an error occurs while validating DPoP proof.
     */
    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {

        String consumerKey = tokenReqDTO.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("DPoP proxy intercepted the token request from the client : %s.",
                    consumerKey));
        }

        String dPoPProof = getDPoPHeader(tokReqMsgCtx);
        try {

            String dPoPState = getApplicationDPoPState(tokenReqDTO.getClientId());
            String tokenBindingType = getApplicationBindingType(tokenReqDTO.getClientId());

            if (DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType) || DPoPState.MANDATORY.equals(dPoPState.toUpperCase())) {
                if (StringUtils.isNotBlank(dPoPProof)) {

                    boolean isValidDPoP = isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx);
                    // If the DPoP proof is provided, it will be handled as a DPoP token request.
                    if (!isValidDPoP) {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("DPoP proof validation failed, Application ID: %s.",
                                    consumerKey));
                        }
                        throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
                    }
                } else {
                    if (DPoPState.MANDATORY.equals(dPoPState)) {
                        throw new IdentityOAuth2Exception("DPoP header is required.");
                    }
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Bearer access token request received from client: %s.",
                                consumerKey));
                    }
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    String.format("Invalid OAuth client: %s.", consumerKey),
                    e);
        }
    }

    /**
     * This method handles DPoP proof validation during pre token renewal.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception If an error occurs while validating DPoP proof.
     */
    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {

        String consumerKey = tokenReqDTO.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("DPoP proxy intercepted the token renewal request from the client : %s.",
                    consumerKey));
        }

        // Check if the Refresh token is of DPoP type.
        boolean isDPoPBinding = false;
        TokenBinding tokenBinding =
                tokenBindingTypeManagerDao.getBindingFromRefreshToken(tokenReqDTO.getRefreshToken());
        if (StringUtils.equalsIgnoreCase(DPoPConstants.DPOP_TOKEN_TYPE, tokenBinding.getBindingType())) {
            isDPoPBinding = true;
        }

        String dPoPProof = getDPoPHeader(tokReqMsgCtx);
        if (isDPoPBinding && StringUtils.isNotBlank(dPoPProof)) {
            // If DPoP proof is provided, then it will be handled as a DPoP token request.
            if (!isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("DPoP proof validation failed for the application Id : %s.",
                            consumerKey));
                }
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
            }
            if (!tokReqMsgCtx.getTokenBinding().getBindingValue().equalsIgnoreCase(tokenBinding.getBindingValue())) {
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
            }
        } else if (isDPoPBinding) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Renewal request received without the DPoP proof from the application Id: %s.",
                        consumerKey));
            }
            throw new IdentityOAuth2Exception("DPoP proof is required.");
        }
    }

    @Override
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ||
                Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    private boolean isValidDPoP(String dPoPProof, OAuth2AccessTokenReqDTO tokenReqDTO,
                                OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJwt = SignedJWT.parse(dPoPProof);
            JWSHeader header = signedJwt.getHeader();
            validateDPoPHeader(header);
            validateDPoPPayload(tokenReqDTO, signedJwt.getJWTClaimsSet());
            return validateSignature(signedJwt, tokReqMsgCtx);
        } catch (ParseException | JOSEException | IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF, e);
        }
    }

    private boolean validateSignature(SignedJWT signedJwt, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws ParseException, JOSEException, IdentityOAuth2Exception {

        JWK jwk = JWK.parse(signedJwt.getHeader().getJWK().toString());
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType(DPoPConstants.DPOP_TOKEN_TYPE);
        boolean isValid = false;

        // Using the EC algorithm.
        if (DPoPConstants.ECDSA_ENCRYPTION.equalsIgnoreCase(jwk.getKeyType().toString())) {
            ECKey ecKey = (ECKey) jwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            isValid = Utils.verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey), signedJwt);
            if (isValid) {
                String thumbprint = Utils.computeThumbprintOfECKey(ecKey);
                tokenBinding.setBindingValue(thumbprint);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(thumbprint));
                DPoPBasedTokenBinder.setTokenBindingValue(tokenBinding.getBindingValue());
                tokReqMsgCtx.setTokenBinding(tokenBinding);
            }
            // Using the RSA algorithm.
        } else if (DPoPConstants.RSA_ENCRYPTION.equalsIgnoreCase(jwk.getKeyType().toString())) {
            RSAKey rsaKey = (RSAKey) jwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            isValid = Utils.verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey), signedJwt);
            if (isValid) {
                String thumbprint = Utils.computeThumbprintOfRSAKey(rsaKey);
                tokenBinding.setBindingValue(thumbprint);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(thumbprint));
                DPoPBasedTokenBinder.setTokenBindingValue(tokenBinding.getBindingValue());
                tokReqMsgCtx.setTokenBinding(tokenBinding);
            }
        } else {
            String msg = String.format("Invalid key algorithm : %s.", jwk.getKeyType().toString());
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            throw new IdentityOAuth2Exception(msg);
        }
        // Set certificate thumbprint as the token binding value.
        return isValid;
    }

    private void validateDPoPHeader(JWSHeader header) throws IdentityOAuth2Exception {

        if (header.getJWK() == null) {
            log.debug("'jwk' is not presented in the DPoP Proof header");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }
        JWSAlgorithm algorithm = header.getAlgorithm();
        if (algorithm == null) {
            log.debug("'algorithm' is not presented in the DPoP Proof header");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }
        if (!DPoPConstants.DPOP_JWT_TYPE.equalsIgnoreCase(header.getType().toString())) {
            log.debug(" typ field value in the DPoP Proof header  is not equal to 'dpop+jwt'");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }
    }

    private void validateDPoPPayload(OAuth2AccessTokenReqDTO tokenReqDTO, JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2Exception, ParseException {

        if (jwtClaimsSet == null) {
            log.debug("'jwtClaimsSet' is missing in the body of a DPoP proof.");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }
        if (!jwtClaimsSet.getClaims().containsKey("jti")) {
            log.debug("'jti' is missing in the 'jwtClaimsSet' of the DPoP proof body.");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);

        }
        HttpServletRequestWrapper requestWrapper = tokenReqDTO.getHttpServletRequestWrapper();
        Object dPoPHttpMethod = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_METHOD);

        // Validate if the DPoP proof HTTP method matches that of the request.
        if (!requestWrapper.getMethod().equalsIgnoreCase(dPoPHttpMethod.toString())) {
            log.debug("DPoP Proof HTTP method mismatch.");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }

        // Validate if the DPoP proof HTTP method matches that of the request.
        Object dPoPContextPath = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_URI);
        if (!requestWrapper.getRequestURL().toString().equalsIgnoreCase(dPoPContextPath.toString())) {
            log.debug("DPoP Proof context path mismatch.");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }

        // DPoP header validity check.
        Timestamp currentTimestamp = new Timestamp(new Date().getTime());
        Date issuedAt = (Date) jwtClaimsSet.getClaim(DPoPConstants.DPOP_ISSUED_AT);
        if (issuedAt == null) {
            log.debug("DPoP Proof missing the 'iat' field.");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }
        boolean isExpired = (currentTimestamp.getTime() - issuedAt.getTime()) > getDPoPValidityPeriod();
        if (isExpired) {
            log.debug("DPoP Proof expired.");
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_PROOF);
        }
    }

    private int getDPoPValidityPeriod() {

        String validityPeriod = IdentityUtil.getProperty(
                DPoPConstants.DPOP_CONFIG_ELEMENT + DPoPConstants.HEADER_VALIDITY);
        return StringUtils.isNotBlank(validityPeriod) ? Integer.parseInt(validityPeriod.trim()) * 1000
                : DPoPConstants.DEFAULT_HEADER_VALIDITY;
    }

    private String getDPoPHeader(OAuthTokenReqMessageContext tokReqMsgCtx) {

        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        if (httpRequestHeaders != null) {
            for (HttpRequestHeader header : httpRequestHeaders) {
                if (header != null && OAuthTokenType.DPOP.name().equalsIgnoreCase(header.getName())) {
                    return ArrayUtils.isNotEmpty(header.getValue()) ? header.getValue()[0] : null;
                }
            }
        }
        return null;
    }

    private String getApplicationDPoPState(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return oauthAppDO != null ? oauthAppDO.getDpopState() : null;
    }

    private String getApplicationBindingType(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return oauthAppDO.getTokenBindingType();
    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {

        if (tokReqMsgCtx.getTokenBinding() != null && (tokReqMsgCtx.getTokenBinding().getBindingType()).contains(
                TokenType.DPOP.toString())) {
            tokenRespDTO.setTokenType(TokenType.DPOP.toString());
        } else {
            tokenRespDTO.setTokenType(TokenType.BEARER.toString());
        }
    }
}
