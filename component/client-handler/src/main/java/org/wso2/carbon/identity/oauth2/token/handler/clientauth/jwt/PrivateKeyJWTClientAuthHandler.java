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

import org.apache.axis2.util.JavaUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.storage.JWTStorageManager;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidator;
import org.wso2.carbon.identity.oauth2.token.handlers.clientauth.AbstractClientAuthHandler;

import java.util.Properties;

public class PrivateKeyJWTClientAuthHandler extends AbstractClientAuthHandler {

    private static Log log = LogFactory.getLog(PrivateKeyJWTClientAuthHandler.class);

    private int rejectBeforePeriod;
    private boolean cacheUsedJTI;
    private boolean preventTokenReuse;
    private String validAudience;
    private String subjectField;
    private String validIssuer;
    private String signedBy;

    private JWTStorageManager JWTStorageManager;
    protected Properties properties;

    private JWTValidator jwtValidator;

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
                JWTStorageManager.persistJWTIdInDB(jti, expiryTime, authenticatedTime);
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
        JWTStorageManager = new JWTStorageManager();
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

            String certificateAliasConfigVal = properties.getProperty(Constants.SIGNED_BY);
            if (StringUtils.isNotEmpty(validSubjectConfigVal)) {
                signedBy = certificateAliasConfigVal;
            } else {
                signedBy = Constants.SP;
            }

            String preventTokenReuseConfigVal = properties.getProperty(Constants.PREVENT_TOKEN_REUSE);
            preventTokenReuse = !StringUtils.isNotEmpty(preventTokenReuseConfigVal) || Boolean.parseBoolean
                    (preventTokenReuseConfigVal);

        } catch (NumberFormatException e) {
            log.warn("Invalid PrivateKeyJWT Validity period found in the configuration. Using default value.");
            rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD;
        }

        jwtValidator = new JWTValidator(rejectBeforePeriod, preventTokenReuse, cacheUsedJTI,
                validAudience, subjectField, validIssuer, signedBy);
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
                return jwtValidator.authenticateTokenRequest(tokReqMsgCtx);
            } catch (IdentityOAuth2Exception e) {
                return false;
            }
        } else {
            return true;
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
        if (StringUtils.isEmpty(paramVal)) {
            return null;
        }
        return paramVal;
    }

}