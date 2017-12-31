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

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidator;
import org.wso2.carbon.identity.oauth2.token.handlers.clientauth.AbstractClientAuthHandler;

import java.text.ParseException;
import java.util.Properties;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.DEFAULT_AUDIENCE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.DEFAULT_ENABLE_JTI_CACHE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.DEFAULT_ISSUER;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_ASSERTION_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.OAUTH_JWT_BEARER_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.PREVENT_TOKEN_REUSE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants.REJECT_BEFORE_PERIOD;

/**
 * Client Authentication handler to implement oidc private_key_jwt client authentication spec
 * http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */
public class PrivateKeyJWTClientAuthHandler extends AbstractClientAuthHandler {

    private static final Log log = LogFactory.getLog(PrivateKeyJWTClientAuthHandler.class);
    private JWTValidator jwtValidator;

    @Override
    public void init(Properties properties) throws IdentityOAuth2Exception {
        authConfig = properties.getProperty(OAuthConstants.CLIENT_AUTH_CREDENTIAL_VALIDATION);
        jwtValidator = createJWTValidator(properties);
    }

    /**
     * Initialize validator parameters
     *
     * @param properties
     */
    private JWTValidator createJWTValidator(Properties properties) {
        boolean enableJTICache = DEFAULT_ENABLE_JTI_CACHE;
        String validAudience = DEFAULT_AUDIENCE;
        String validIssuer = DEFAULT_ISSUER;
        boolean preventTokenReuse = PREVENT_TOKEN_REUSE;
        int notAcceptBeforeTimeInMins = DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
        try {
            String rejectBeforePeriodConfigVal = properties.getProperty(REJECT_BEFORE_PERIOD);
            if (isNotEmpty(rejectBeforePeriodConfigVal)) {
                notAcceptBeforeTimeInMins = Integer.parseInt(rejectBeforePeriodConfigVal);
            }
            if (log.isDebugEnabled()) {
                log.debug("PrivateKeyJWT Validity period is set to:" + notAcceptBeforeTimeInMins);
            }
        } catch (NumberFormatException e) {
            log.warn("Invalid PrivateKeyJWT Validity period found in the configuration. Using default value:" +
                    DEFAULT_VALIDITY_PERIOD_IN_MINUTES);
        }
        return new JWTValidator(notAcceptBeforeTimeInMins, preventTokenReuse, enableJTICache,
                validAudience, validIssuer);
    }

    @Override
    public boolean canAuthenticate(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        String clientAssertionType = getRequestParameter(tokReqMsgCtx, OAUTH_JWT_ASSERTION_TYPE);
        String clientAssertion = getRequestParameter(tokReqMsgCtx, OAUTH_JWT_ASSERTION);

        return isValidJWTClientAssertionRequest(clientAssertionType, clientAssertion);
    }

    /**
     * Check whether the client_assertion_type and client_assertion is valid
     *
     * @param clientAssertionType
     * @param clientAssertion
     * @return
     */
    private boolean isValidJWTClientAssertionRequest(String clientAssertionType, String clientAssertion) {
        if (log.isDebugEnabled()) {
            log.debug("Authenticate Requested with : " + clientAssertionType + " and " +
                    "private_key_jwt: " + clientAssertion);
        }
        return OAUTH_JWT_BEARER_GRANT_TYPE.equals(clientAssertionType) && isNotEmpty(clientAssertion);
    }

    @Override
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        boolean isValid = false;
        try {
            SignedJWT signedJWT = getSignedJWT(tokReqMsgCtx);
            isValid = jwtValidator.isValidToken(signedJWT);
            if (isValid && StringUtils.isEmpty(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId())) {
                ReadOnlyJWTClaimsSet claimsSet = jwtValidator.getClaimSet(signedJWT);
                String jwtSubject = jwtValidator.resolveSubject(claimsSet);
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setClientId(jwtSubject);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred validating the signed JWT", e);
            return false;
        }
        return isValid;
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
            if (param.getKey().equals(paramName) && !ArrayUtils.isEmpty(param.getValue())) {
                paramVal = param.getValue()[0];
                break;
            }
        }
        if (isEmpty(paramVal)) {
            return null;
        }
        return paramVal;
    }

    /**
     * @param tokReqMsgCtx Token message request context
     * @return signedJWT
     */
    private SignedJWT getSignedJWT(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        SignedJWT signedJWT;
        String assertion;
        assertion = getRequestParameter(tokReqMsgCtx, OAUTH_JWT_ASSERTION);
        if (isEmpty(assertion)) {
            return null;
        }

        try {
            signedJWT = SignedJWT.parse(assertion);
            logJWT(signedJWT);
        } catch (ParseException e) {
            String errorMessage = "Error while parsing the JWT";
            log.error(errorMessage, e);
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        if (signedJWT == null) {
            String errorMessage = "No Valid Assertion was found for " + OAUTH_JWT_BEARER_GRANT_TYPE;
            log.error(errorMessage);
            throw new IdentityOAuth2Exception(errorMessage);
        }
        return signedJWT;
    }

    /**
     * @param signedJWT the signedJWT to be logged
     */
    private void logJWT(SignedJWT signedJWT) {
        if (log.isDebugEnabled()) {
            log.debug("JWT Header: " + signedJWT.getHeader().toJSONObject().toString());
            log.debug("JWT Payload: " + signedJWT.getPayload().toJSONObject().toString());
            log.debug("Signature: " + signedJWT.getSignature().toString());
        }
    }
}
