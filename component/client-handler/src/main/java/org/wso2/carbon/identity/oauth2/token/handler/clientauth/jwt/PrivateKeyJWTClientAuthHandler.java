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

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
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

/**
 * Client Authentication handler to implement oidc private_key_jwt client authentication spec
 * http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */
public class PrivateKeyJWTClientAuthHandler extends AbstractClientAuthHandler {

    private static final Log log = LogFactory.getLog(PrivateKeyJWTClientAuthHandler.class);

    private int notAcceptBeforeTimeInMins;
    private boolean enableJTICache;
    private boolean preventTokenReuse;
    private String validAudience;
    private String validIssuer;

    private JWTValidator jwtValidator;

    @Override
    public void init(Properties properties) throws IdentityOAuth2Exception {
        authConfig = properties.getProperty(OAuthConstants.CLIENT_AUTH_CREDENTIAL_VALIDATION);
        initialiseJWTValidatorVariables(properties);
        jwtValidator = new JWTValidator(notAcceptBeforeTimeInMins, preventTokenReuse, enableJTICache,
                validAudience, validIssuer);
    }

    /**
     * Initialize validator parameters
     * @param properties
     */
    private void initialiseJWTValidatorVariables(Properties properties) {
        try {
            String rejectBeforePeriodConfigVal = properties.getProperty(Constants.VALIDITY_PERIOD);
            if (isNotEmpty(rejectBeforePeriodConfigVal)) {
                notAcceptBeforeTimeInMins = Integer.parseInt(rejectBeforePeriodConfigVal);
            } else {
                notAcceptBeforeTimeInMins = Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
            }
            enableJTICache = Constants.DEFAULT_ENABLE_JTI_CACHE;
            validAudience = Constants.DEFAULT_AUDIENCE;
            validIssuer = Constants.DEFAULT_ISSUER;
            preventTokenReuse = Constants.PREVENT_TOKEN_REUSE;

        } catch (NumberFormatException e) {
            log.warn("Invalid PrivateKeyJWT Validity period found in the configuration. Using default value.");
            notAcceptBeforeTimeInMins = Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
        }
    }

    @Override
    public boolean canAuthenticate(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        String clientAssertionType = getRequestParameter(tokReqMsgCtx, Constants.OAUTH_JWT_ASSERTION_TYPE);
        String clientAssertion = getRequestParameter(tokReqMsgCtx, Constants.OAUTH_JWT_ASSERTION);

        return isValidJWTClientAssertionRequest(clientAssertionType, clientAssertion);
        //TODO check validate SAML_Bearer
    }

    /**
     * Check whether the client_assertion_type and client_assertion is valid
     * @param clientAssertionType
     * @param clientAssertion
     * @return
     */
    private boolean isValidJWTClientAssertionRequest(String clientAssertionType, String clientAssertion) {
        if (log.isDebugEnabled()) {
            log.debug("Authenticate Requested with : " + Constants.OAUTH_JWT_ASSERTION_TYPE + " and " +
                    "private_key_jwt: " + clientAssertion);
        }
        return Constants.OAUTH_JWT_BEARER_GRANT_TYPE.equals(clientAssertionType) && isNotEmpty(clientAssertion);
    }

    @Override
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        try {
            SignedJWT signedJWT = getSignedJWT(tokReqMsgCtx);
            return jwtValidator.isValidToken(signedJWT);
        } catch (IdentityOAuth2Exception e) {
            return false;
        }
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
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String assertion = null;
        SignedJWT signedJWT = null;
        for (RequestParameter param : params) {
            if (param.getKey().equals(Constants.OAUTH_JWT_ASSERTION) && !ArrayUtils.isEmpty(param.getValue())) {
                assertion = param.getValue()[0];
                break;
            }
        }
        if (isEmpty(assertion)) {
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
        if (signedJWT == null) {
            handleException("No Valid Assertion was found for " + Constants.OAUTH_JWT_BEARER_GRANT_TYPE);
        }
        return signedJWT;
    }

    /**
     * Handle error scenarios
     * @param errorMessage
     * @throws IdentityOAuth2Exception
     */
    private void handleException(String errorMessage) throws IdentityOAuth2Exception {
        log.error(errorMessage);
        throw new IdentityOAuth2Exception(errorMessage);
    }

    /**
     * @param signedJWT the signedJWT to be logged
     */
    private void logJWT(SignedJWT signedJWT) {
        log.debug("JWT Header: " + signedJWT.getHeader().toJSONObject().toString());
        log.debug("JWT Payload: " + signedJWT.getPayload().toJSONObject().toString());
        log.debug("Signature: " + signedJWT.getSignature().toString());
    }
}