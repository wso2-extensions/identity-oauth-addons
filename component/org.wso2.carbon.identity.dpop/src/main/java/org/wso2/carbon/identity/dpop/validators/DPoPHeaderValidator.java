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

package org.wso2.carbon.identity.dpop.validators;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

/**
 * DPoP Header  validator.
 */
public class DPoPHeaderValidator {

    static final Log log = LogFactory.getLog(DPoPHeaderValidator.class);

    /**
     * Extract DPoP header from the headers.
     *
     * @param tokReqMsgCtx Message context of token request.
     * @return DPoP header.
     */
    public static String getDPoPHeader(OAuthTokenReqMessageContext tokReqMsgCtx) {

        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        if (httpRequestHeaders != null) {
            for (HttpRequestHeader header : httpRequestHeaders) {
                if (header != null && DPoPConstants.OAUTH_DPOP_HEADER.equalsIgnoreCase(header.getName())) {
                    return ArrayUtils.isNotEmpty(header.getValue()) ? header.getValue()[0] : null;
                }
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * Get Oauth application Access token binding type.
     *
     * @param consumerKey Consumer Key.
     * @return Access token binding type of the oauth application.
     * @throws InvalidOAuthClientException Error while getting the Oauth application information.
     * @throws IdentityOAuth2Exception Error while getting the Oauth application information.
     */
    public static String getApplicationBindingType(String consumerKey) throws
            IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        return oauthAppDO.getTokenBindingType();
    }

    /**
     * Validate dpop proof header.
     *
     * @param httpMethod HTTP method of the request.
     * @param httpURL HTTP URL of the request,
     * @param dPoPProof DPoP header of the request.
     * @return
     * @throws ParseException Error while retrieving the signedJwt.
     * @throws IdentityOAuth2Exception Error while validating the dpop proof.
     */
    public static boolean isValidDPoPProof(String httpMethod, String httpURL, String dPoPProof)
            throws ParseException, IdentityOAuth2Exception {

        SignedJWT signedJwt = SignedJWT.parse(dPoPProof);
        JWSHeader header = signedJwt.getHeader();

        return validateDPoPPayload(httpMethod, httpURL, signedJwt.getJWTClaimsSet()) && validateDPoPHeader(header);
    }

    /**
     * Set token binder information if dpop proof is valid.
     *
     * @param dPoPProof DPoP proof header.
     * @param tokenReqDTO Token request dto.
     * @param tokReqMsgCtx Message context of token request.
     * @return
     * @throws IdentityOAuth2Exception Error while validating the dpop proof.
     */
    public static boolean isValidDPoP(String dPoPProof, OAuth2AccessTokenReqDTO tokenReqDTO,
            OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        try {
            HttpServletRequest request = tokenReqDTO.getHttpServletRequestWrapper();
            String httpMethod = request.getMethod();
            String httpURL = request.getRequestURL().toString();
            if (isValidDPoPProof(httpMethod, httpURL, dPoPProof)) {
                String thumbprint = Utils.getThumbprintOfKeyFromDpopProof(dPoPProof);
                if (StringUtils.isNotBlank(thumbprint)) {
                    TokenBinding tokenBinding = new TokenBinding();
                    tokenBinding.setBindingType(DPoPConstants.DPOP_TOKEN_TYPE);
                    tokenBinding.setBindingValue(thumbprint);
                    tokenBinding.setBindingReference(DigestUtils.md5Hex(thumbprint));
                    tokReqMsgCtx.setTokenBinding(tokenBinding);
                    setCnFValue(tokReqMsgCtx, tokenBinding.getBindingValue());
                    return true;
                }
            }
        } catch (ParseException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return false;
    }

    private static boolean validateDPoPHeader(JWSHeader header) throws IdentityOAuth2Exception {

        return checkJwk(header) && checkAlg(header) && checkHeaderType(header);
    }

    private static boolean validateDPoPPayload(String httpMethod, String httpURL, JWTClaimsSet jwtClaimsSet)
            throws IdentityOAuth2Exception {

        return checkJwtClaimSet(jwtClaimsSet) && checkDPoPHeaderValidity(jwtClaimsSet) && checkJti(jwtClaimsSet) &&
                checkHTTPMethod(httpMethod, jwtClaimsSet) && checkHTTPURI(httpURL, jwtClaimsSet);
    }

    private static boolean checkJwk(JWSHeader header) throws IdentityOAuth2ClientException {

        if (header.getJWK() == null) {
            if (log.isDebugEnabled()) {
                log.debug("'jwk' is not presented in the DPoP Proof header");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private static boolean checkAlg(JWSHeader header) throws IdentityOAuth2ClientException {

        JWSAlgorithm algorithm = header.getAlgorithm();
        if (algorithm == null) {
            if (log.isDebugEnabled()) {
                log.debug("'algorithm' is not presented in the DPoP Proof header");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private static boolean checkHeaderType(JWSHeader header) throws IdentityOAuth2ClientException {

        if (!DPoPConstants.DPOP_JWT_TYPE.equalsIgnoreCase(header.getType().toString())) {
            if (log.isDebugEnabled()) {
                log.debug(" typ field value in the DPoP Proof header  is not equal to 'dpop+jwt'");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        return true;
    }

    private static boolean checkJwtClaimSet(JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        if (jwtClaimsSet == null) {
            if (log.isDebugEnabled()) {
                log.debug("'jwtClaimsSet' is missing in the body of a DPoP proof.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private static boolean checkDPoPHeaderValidity(JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        Timestamp currentTimestamp = new Timestamp(new Date().getTime());
        Date issuedAt = (Date) jwtClaimsSet.getClaim(DPoPConstants.DPOP_ISSUED_AT);
        if (issuedAt == null) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP Proof missing the 'iat' field.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        boolean isExpired = (currentTimestamp.getTime() - issuedAt.getTime()) > getDPoPValidityPeriod();
        if (isExpired) {
            String error = "Expired DPoP Proof";
            if (log.isDebugEnabled()) {
                log.debug(error);
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, error);
        }
        return true;
    }

    private static boolean checkJti(JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        if (!jwtClaimsSet.getClaims().containsKey(DPoPConstants.JTI)) {
            if (log.isDebugEnabled()) {
                log.debug("'jti' is missing in the 'jwtClaimsSet' of the DPoP proof body.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private static boolean checkHTTPMethod(String httpMethod, JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        Object dPoPHttpMethod = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_METHOD);

        // Check if the DPoP proof HTTP method is empty.
        if (dPoPHttpMethod == null) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP Proof HTTP method empty.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        // Validate if the DPoP proof HTTP method matches that of the request.
        if (!httpMethod.equalsIgnoreCase(dPoPHttpMethod.toString())) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP Proof HTTP method mismatch.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        return true;
    }

    private static boolean checkHTTPURI(String httpUrl, JWTClaimsSet jwtClaimsSet) throws IdentityOAuth2ClientException {

        Object dPoPContextPath = jwtClaimsSet.getClaim(DPoPConstants.DPOP_HTTP_URI);

        if (dPoPContextPath == null) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP Proof context path empty.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }

        // Validate if the DPoP proof HTTP URI matches that of the request.
        if (!httpUrl.equalsIgnoreCase(dPoPContextPath.toString())) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP Proof context path mismatch.");
            }
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_ERROR);
        }
        return true;
    }

    private static int getDPoPValidityPeriod() {
        Object validityPeriodObject = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), OauthDPoPInterceptorHandlerProxy.class.getName())
                .getProperties().get(DPoPConstants.VALIDITY_PERIOD);

        if (validityPeriodObject == null){
            return DPoPConstants.DEFAULT_HEADER_VALIDITY;
        }

        String validityPeriodValue = validityPeriodObject.toString();

        if (StringUtils.isNotBlank(validityPeriodValue)) {
            if (StringUtils.isNumeric(validityPeriodValue)) {
                return Integer.parseInt(validityPeriodValue.trim()) * 1000;
            }
            log.info("Configured dpop validity period is set to an invalid value.Hence the default validity " +
                    "period will be used.");
            return DPoPConstants.DEFAULT_HEADER_VALIDITY;
        }
        return DPoPConstants.DEFAULT_HEADER_VALIDITY;
    }

    private static void setCnFValue(OAuthTokenReqMessageContext tokReqMsgCtx, String tokenBindingValue) {

        JSONObject obj = new JSONObject();
        obj.put(DPoPConstants.JWK_THUMBPRINT, tokenBindingValue);
        tokReqMsgCtx.addProperty(DPoPConstants.CNF, obj);
    }
}
