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
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.constant.Constants;
import org.wso2.carbon.identity.dpop.util.OuthTokenType;
import org.wso2.carbon.identity.oauth.common.DPoPState;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

import javax.servlet.http.HttpServletRequestWrapper;

/**
 * This class extends AbstractOAuthEventInterceptor and listen to oauth token related events.
 * In this class, DPoP proof validation will be handled for DPoP token requests.
 */
public class OauthDPoPInterceptorHandlerProxy extends AbstractOAuthEventInterceptor {

    private static final Log log = LogFactory.getLog(OauthDPoPInterceptorHandlerProxy.class);

    /**
     * This method handles DPoP proof validation during pre token issuance.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("DPoP proxy intercepted the token request from the client : %s.",
                    tokenReqDTO.getClientId()));
        }

        String dPoPProof = getDPoPHeader(tokReqMsgCtx);
        try {
            DPoPState dPoPState = getApplicationDPoPState(tokenReqDTO.getClientId());
            if (DPoPState.ENABLED.equals(dPoPState) || DPoPState.MANDATORY.equals(dPoPState)) {
                if (StringUtils.isNotBlank(dPoPProof)) {
                    // If the DPoP proof is provided, it will be handled as a DPoP token request.
                    if (!isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx, false)) {
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("DPoP proof validation failed, Application ID: %s.",
                                    tokenReqDTO.getClientId()));
                        }
                        throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
                    }
                } else {
                    if (DPoPState.MANDATORY.equals(dPoPState)) {
                        throw new IdentityOAuth2Exception("DPoP Header is Required.");
                    }
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Bearer access token request received from: %s.",
                                tokenReqDTO.getClientId()));
                    }
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    String.format("Invalid OAuth client: %s.", tokenReqDTO.getClientId()),
                    e);
        }
    }

    /**
     * This method handles DPoP proof validation during pre token renewal.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the pre token renewal event with the DPoP proof for the " +
                    "application Id: %s.", tokenReqDTO.getClientId()));
        }

        // Check if the Refresh token is of DPoP type.
        boolean isDPoPBinding = false;
        TokenBinding tokenBinding = getBindingFromRefreshToken(tokenReqDTO.getRefreshToken());
        if (tokenBinding != null && Constants.DPOP_TOKEN_TYPE.equalsIgnoreCase(tokenBinding.getBindingType())) {
            isDPoPBinding = true;
        }

        String dPoPProof = getDPoPHeader(tokReqMsgCtx);
        if (isDPoPBinding && StringUtils.isNotBlank(dPoPProof)) {
            // If DPoP proof is provided, then it will be handled as a DPoP token request.
            if (!isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx, true)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("DPoP proof validation failed for the application Id : %s.",
                            tokenReqDTO.getClientId()));
                }
                throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
            }
            if (!tokReqMsgCtx.getTokenBinding().getBindingValue().equalsIgnoreCase(tokenBinding.getBindingValue())) {
                throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
            }
        } else if (isDPoPBinding) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Renewal request received without the DPoP proof from the application Id: %s.",
                        tokenReqDTO.getClientId()));
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
                                OAuthTokenReqMessageContext tokReqMsgCtx, boolean isRenewalRequest)
            throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJwt = SignedJWT.parse(dPoPProof);
            JWSHeader header = signedJwt.getHeader();
            validateDPoPHeader(header);
            validateDPoPPayload(tokenReqDTO, signedJwt.getJWTClaimsSet(), isRenewalRequest);
            return validateSignature(signedJwt, tokReqMsgCtx);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF, e);
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF, e);
        }
    }

    private boolean validateSignature(SignedJWT signedJwt, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws ParseException, JOSEException {

        JWK jwk = JWK.parse(signedJwt.getHeader().getJWK().toString());
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType(Constants.DPOP_TOKEN_TYPE);
        boolean isValid = false;

        // Using the EC algorithm.
        if (Constants.ECDSA_ENCRYPTION.equalsIgnoreCase(jwk.getKeyType().toString())) {
            ECKey ecKey = (ECKey) jwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            isValid = verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey), signedJwt);
            if (isValid) {
                String publicKey = computeThumbprintOfKey(ecKey);
                tokenBinding.setBindingValue(publicKey);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(publicKey));
            }
            // Using the RSA algorithm.
        } else if (Constants.RSA_ENCRYPTION.equalsIgnoreCase(jwk.getKeyType().toString())) {
            RSAKey rsaKey = (RSAKey) jwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            isValid = verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey), signedJwt);
            if (isValid) {
                String publicKey = computeThumbprintOfKey(rsaKey);
                tokenBinding.setBindingValue(publicKey);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(publicKey));
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid key algorithm : %s.", jwk.getKeyType().toString()));
            }
        }
        // Set certificate thumbprint as the token binding value.
        tokReqMsgCtx.setTokenBinding(tokenBinding);
        return isValid;
    }

    private void validateDPoPHeader(JWSHeader header) throws IdentityOAuth2Exception {

        if (header.getJWK() == null) {
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }
        JWSAlgorithm algorithm = header.getAlgorithm();
        if (algorithm == null) {
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }
        if (!Constants.DPOP_JWT_TYPE.equalsIgnoreCase(header.getType().toString())) {
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }
    }

    private String computeThumbprintOfKey(JWK rsaKey) throws JOSEException {

        return rsaKey.computeThumbprint().toString();
    }

    private boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt) throws JOSEException {

        return signedJwt.verify(jwsVerifier);
    }

    private void validateDPoPPayload(OAuth2AccessTokenReqDTO tokenReqDTO, JWTClaimsSet jwtClaimsSet,
                                     boolean isRefreshRequest) throws IdentityOAuth2Exception {

        if (jwtClaimsSet == null) {
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }

        HttpServletRequestWrapper requestWrapper = tokenReqDTO.getHttpServletRequestWrapper();
        Object dPoPHttpMethod = jwtClaimsSet.getClaim(Constants.DPOP_HTTP_METHOD);

        // Validate if the DPoP proof HTTP method matches that of the request.
        if (!requestWrapper.getMethod().equalsIgnoreCase(dPoPHttpMethod.toString())) {
            log.debug("DPoP Proof HTTP method mismatch.");
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }

        // Validate if the DPoP proof HTTP method matches that of the request.
        Object dPoPContextPath = jwtClaimsSet.getClaim(Constants.DPOP_HTTP_URI);
        if (!requestWrapper.getRequestURL().toString().equalsIgnoreCase(dPoPContextPath.toString())) {
            log.debug("DPoP Proof context path mismatch.");
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }

        // DPoP header validity check.
        Timestamp currentTimestamp = new Timestamp(new Date().getTime());
        Date issuedAt = (Date) jwtClaimsSet.getClaim(Constants.DPOP_ISSUED_AT);
        if (issuedAt == null) {
            log.debug("DPoP Proof missing the 'iat' field.");
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }
        boolean isExpired = (currentTimestamp.getTime() - issuedAt.getTime()) > getDPoPValidityPeriod();
        if (!isRefreshRequest && isExpired) {
            log.debug("DPoP Proof expired.");
            throw new IdentityOAuth2Exception(Constants.INVALID_DPOP_PROOF);
        }
    }

    private int getDPoPValidityPeriod() {

        String validityPeriod = IdentityUtil.getProperty(Constants.DPOP_CONFIG_ELEMENT + Constants.HEADER_VALIDITY);
        return StringUtils.isNotBlank(validityPeriod) ? Integer.parseInt(validityPeriod.trim()) * 1000
                : Constants.DEFAULT_HEADER_VALIDITY;
    }

    private String getDPoPHeader(OAuthTokenReqMessageContext tokReqMsgCtx) {

        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        for (HttpRequestHeader header : httpRequestHeaders) {
            if (OuthTokenType.DPOP.name().equalsIgnoreCase(header.getName())) {
                return ArrayUtils.isNotEmpty(header.getValue()) ? header.getValue()[0] : null;
            }
        }
        return null;
    }

    // TODO Fix this method.
    private TokenBinding getBindingFromRefreshToken(String refreshToken) throws IdentityOAuth2Exception {
        try {
            Connection connection = IdentityDatabaseUtil.getDBConnection(false);
            PreparedStatement prepStmt;
            ResultSet resultSet;
            String sql =
                    "SELECT token_binding_type,\n" +
                            "       token_binding_value\n" +
                            "FROM   idn_oauth2_token_binding\n" +
                            "WHERE  token_binding_ref = (SELECT token_binding_ref\n" +
                            "                            FROM   idn_oauth2_access_token\n" +
                            "                            WHERE  refresh_token = ?) ";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, refreshToken);
            TokenBinding tokenBinding = new TokenBinding();
            resultSet = prepStmt.executeQuery();
            while (resultSet.next()) {
                tokenBinding.setBindingType(resultSet.getString(1));
                tokenBinding.setBindingValue(resultSet.getString(2));
            }
            connection.close();
            return tokenBinding;
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
    }

    private DPoPState getApplicationDPoPState(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return DPoPState.valueOf(oauthAppDO.getDpopState().toUpperCase());
    }
}
