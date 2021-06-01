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
import org.apache.axiom.om.OMElement;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.util.DPoPConstants;
import org.wso2.carbon.identity.dpop.util.OuthTokenType;
import org.wso2.carbon.identity.oauth.common.DPoPTokenState;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.ws.rs.HttpMethod;
import javax.xml.namespace.QName;
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

/**
 * This class extends AbstractOAuthEventInterceptor and listen to oauth token related events.
 * In this class, DPoP proof validation will be handle for DPoP token requests.
 */
public class OauthDPoPInterceptorHandlerProxy extends AbstractOAuthEventInterceptor {

    private static final Log log = LogFactory.getLog(OauthDPoPInterceptorHandlerProxy.class);
    private static final String ECDSA_ENCRYPTION = "EC";
    private static final String RSA_ENCRYPTION = "RSA";

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
            log.debug(String.format("Listening to the pre token issue event with the DPoP proof for the " +
                    "application: %s", tokenReqDTO.getClientId()));
        }
        String dPoPProof = getDPoPHeader(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders());

        try {
            String dPoPStateOfOAuthApplication = getDPoPStateOfOAuthApplication(tokenReqDTO.getClientId());
            if (DPoPTokenState.ENABLED.toString().equalsIgnoreCase(dPoPStateOfOAuthApplication)
                    || DPoPTokenState.MANDATORY.toString().equalsIgnoreCase(dPoPStateOfOAuthApplication)) {
                if (StringUtils.isNotBlank(dPoPProof)) {
                    /*
                     * if the DPoP proof is provided then it will be handle as DPoP token request
                     */
                    if (!isValidDPoP(dPoPProof, tokReqMsgCtx, false)) {
                        if (log.isDebugEnabled()) {
                            log.debug("DPoP proof validation failed, Application ID: " + tokenReqDTO.getClientId());
                        }
                        throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
                    }
                } else {
                    if (DPoPTokenState.MANDATORY.toString().equalsIgnoreCase(dPoPStateOfOAuthApplication)) {
                        throw new IdentityOAuth2Exception("DPoP Header is Required");
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Bearer access token request received from: " + tokenReqDTO.getClientId());
                    }
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Invalid OAuth Client", e);
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
                    "application: %s", tokenReqDTO.getClientId()));
        }
        boolean isDPoPBinding = false;
        TokenBinding tokenBinding = getBindingFromRefreshToken(tokenReqDTO.getRefreshToken());
        if ("DPoP".equalsIgnoreCase(tokenBinding.getBindingType())) {
            isDPoPBinding = true;
        }

        String dPoPProof = getDPoPHeader(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders());

        if (isDPoPBinding && StringUtils.isNotBlank(dPoPProof)) {
            /*
             * if the DPoP proof is provided then it will be handle as DPoP token request
             */
            if (!isValidDPoP(dPoPProof, tokReqMsgCtx, true)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP proof validation failed, Application ID: " + tokenReqDTO.getClientId());
                }
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
            }
            if (!tokReqMsgCtx.getTokenBinding().getBindingValue().equalsIgnoreCase(tokenBinding.getBindingValue())) {
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
            }

        } else if (isDPoPBinding) {
            if (log.isDebugEnabled()) {
                log.debug("Bearer access token renewal request received from: " + tokenReqDTO.getClientId());
            }
            throw new IdentityOAuth2Exception("DPoP proof is required");
        }
    }

    @Override
    public boolean isEnabled() {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ||
                Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    private boolean isValidDPoP(String dPoPProof, OAuthTokenReqMessageContext tokReqMsgCtx, boolean isFreshRequest)
            throws IdentityOAuth2Exception {
        try {
            SignedJWT signedJwt = SignedJWT.parse(dPoPProof);
            JWSHeader header = signedJwt.getHeader();
            validateDPoPHeader(header);
            dPoPPayloadCheck(signedJwt.getJWTClaimsSet(), new Timestamp(new Date().getTime()), isFreshRequest);
            return isValidSignature(signedJwt, tokReqMsgCtx);

        } catch (ParseException e) {
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR, e);
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
    }

    private boolean isValidSignature(SignedJWT signedJwt, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws ParseException, JOSEException {
        JWK parseJwk = JWK.parse(signedJwt.getHeader().toString());
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType(DPoPConstants.DPOP_TOKEN_TYPE);
        boolean validSignature = false;

        if (ECDSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            ECKey ecKey = (ECKey) parseJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            validSignature = verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey), signedJwt);
            if (validSignature) {
                String publicKey = computeThumbprintOfKey(ecKey);
                tokenBinding.setBindingValue(publicKey);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(publicKey));
            }
        } else if (RSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            RSAKey rsaKey = (RSAKey) parseJwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            validSignature = verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey), signedJwt);
            if (validSignature) {
                String publicKey = computeThumbprintOfKey(rsaKey);
                tokenBinding.setBindingValue(publicKey);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(publicKey));
            }
        }
        tokReqMsgCtx.setTokenBinding(tokenBinding);
        return validSignature;
    }

    private void validateDPoPHeader(JWSHeader header) throws IdentityOAuth2Exception {
        if (header.getJWK() == null) {
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
        }
        JWSAlgorithm algorithm = header.getAlgorithm();
        if (algorithm == null) {
            throw new IdentityOAuth2Exception("DPoP Proof validation failed, Encryption algorithm is not found");
        }
        if (!DPoPConstants.DPOP_JWT_TYPE.equalsIgnoreCase(header.getType().toString())) {
            throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
        }
    }

    private String computeThumbprintOfKey(JWK rsaKey) throws JOSEException {
        return rsaKey.computeThumbprint().toString();
    }

    private boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt) throws JOSEException {
        return signedJwt.verify(jwsVerifier);
    }

    private void dPoPPayloadCheck(JWTClaimsSet jwtClaimsSet, Timestamp currentTimestamp, boolean isRefreshRequest)
            throws IdentityOAuth2Exception {
        if (jwtClaimsSet == null) {
            throw new IdentityOAuth2Exception("DPoP proof payload is invalid");
        } else {

            Object dPoPHttpMethod = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_METHOD);

            if (dPoPHttpMethod == null || !HttpMethod.POST.equalsIgnoreCase(dPoPHttpMethod.toString())) {
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
            }

            // TODO: Validate htu
            if (jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_URI) == null) {
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
            }

            if (jwtClaimsSet.getClaim(DPoPConstants.DPOP_ISSUE_AT) == null) {
                throw new IdentityOAuth2Exception(DPoPConstants.INVALID_DPOP_ERROR);
            }

            Date issueAt = (Date) jwtClaimsSet.getClaim(DPoPConstants.DPOP_ISSUE_AT);

            IdentityConfigParser configParser = IdentityConfigParser.getInstance();
            OMElement oauthElem = configParser.getConfigElement(DPoPConstants.OAUTH_CONFIG_ELEMENT);
            if (!isRefreshRequest
                    && (((currentTimestamp.getTime() - issueAt.getTime()) / 1000) > getDPoPValidityPeriod(oauthElem))) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP Proof expired");
                }
                throw new IdentityOAuth2Exception("Expired DPoP Proof");
            }
        }
    }

    private int getDPoPValidityPeriod(OMElement oauthElem) {
        OMElement dPopConfigElem = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS(DPoPConstants.DPOP_CONFIG_ELEMENT));
        if (dPopConfigElem != null) {
            OMElement dpopHeaderValidity =
                    dPopConfigElem.getFirstChildWithName(getQNameWithIdentityNS(DPoPConstants.DPOP_CONFIG_HEADER_VALIDITY));
            if (dpopHeaderValidity != null && StringUtils.isNotBlank(dpopHeaderValidity.getText())) {
                return Integer.parseInt(dpopHeaderValidity.getText().trim());
            }
        }
        return 60;
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private String getDPoPHeader(HttpRequestHeader[] httpRequestHeaders) {
        for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
            if (OuthTokenType.DPOP.name().equalsIgnoreCase(httpRequestHeader.getName())) {
                if (!ArrayUtils.isEmpty(httpRequestHeader.getValue())) {
                    return httpRequestHeader.getValue()[0];
                }
            }
        }
        return null;
    }

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

    private String getDPoPStateOfOAuthApplication(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return oauthAppDO.getDpopState() != null ? oauthAppDO.getDpopState() : DPoPTokenState.DISABLED.toString();
    }
}
