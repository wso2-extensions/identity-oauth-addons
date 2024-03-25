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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.dao.DPoPTokenManagerDAO;
import org.wso2.carbon.identity.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Map;

/**
 * This class extends {@link AbstractOAuthEventInterceptor} and listen to oauth token related events.
 * In this class, DPoP proof validation will be handled for DPoP token requests.
 */
public class OauthDPoPInterceptorHandlerProxy extends AbstractOAuthEventInterceptor {

    private static final Log log = LogFactory.getLog(OauthDPoPInterceptorHandlerProxy.class);
    private DPoPTokenManagerDAO
            tokenBindingTypeManagerDao = DPoPDataHolder.getInstance().getTokenBindingTypeManagerDao();

    @Override
    public void onPostAuthzCodeIssue(OAuthAuthzReqMessageContext oAuthAuthzMsgCtx, AuthzCodeDO authzCodeDO)
            throws IdentityOAuth2Exception {

        Map<String, String[]> requestparams = (Map<String, String[]>) oAuthAuthzMsgCtx.getAuthorizationReqDTO()
                .getProperty(DPoPConstants.OAUTH_AUTHZ_REQUEST_PARAMS);
        if (requestparams == null) {
            throw new IdentityOAuth2Exception("Error while retrieving request parameters.");
        }
        if (requestparams.containsKey(DPoPConstants.DPOP_JKT)) {
            //create cache entry for dpop jkt
            //retrive at preTokenIssue and compare
            log.info("DPoP JWK thumbprint value is received in the authorization request : " +
                    requestparams.get(DPoPConstants.DPOP_JKT)[0]);
        }
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {

        String consumerKey = tokenReqDTO.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("DPoP proxy intercepted the token request from the client : %s.", consumerKey));
        }
        try {
            String tokenBindingType = DPoPHeaderValidator.getApplicationBindingType(tokenReqDTO.getClientId());
            if (DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType)) {

                String dPoPProof = DPoPHeaderValidator.getDPoPHeader(tokReqMsgCtx);
                if (StringUtils.isBlank(dPoPProof)) {
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            "DPoP header is required.");
                }
                boolean isValidDPoP = DPoPHeaderValidator.isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx);
                if (!isValidDPoP) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("DPoP proof validation failed, Application ID: %s.", consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Bearer access token request received from client: %s.", consumerKey));
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
        }
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {

        String consumerKey = tokenReqDTO.getClientId();
        if (log.isDebugEnabled()) {
            log.debug(String.format("DPoP proxy intercepted the token renewal request from the client : %s.",
                    consumerKey));
        }
        try {
            String tokenBindingType = DPoPHeaderValidator.getApplicationBindingType(tokenReqDTO.getClientId());
            TokenBinding tokenBinding =
                    tokenBindingTypeManagerDao.getTokenBinding(tokenReqDTO.getRefreshToken(), OAuth2Util.isHashEnabled());
            if (tokenBinding != null) {
                if (!DPoPConstants.DPOP_TOKEN_TYPE.equals(tokenBindingType)) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("DPoP based token binding is not enabled  for the " +
                                "application Id : %s.", consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_CLIENT,
                            DPoPConstants.INVALID_CLIENT_ERROR);
                }

                String dPoPProof = DPoPHeaderValidator.getDPoPHeader(tokReqMsgCtx);
                if (StringUtils.isBlank(dPoPProof)) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Renewal request received without the DPoP proof from the " +
                                "application Id: %s.", consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            "DPoP proof is required.");
                }

                if (!DPoPHeaderValidator.isValidDPoP(dPoPProof, tokenReqDTO, tokReqMsgCtx)) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("DPoP proof validation failed for the application Id : %s.",
                                consumerKey));
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR);
                }
                if (!tokReqMsgCtx.getTokenBinding().getBindingValue().equalsIgnoreCase(tokenBinding.getBindingValue())) {
                    if (log.isDebugEnabled()) {
                        log.debug("DPoP proof thumbprint value of the public key is not equal to binding value from" +
                                " the refresh token.");
                    }
                    throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF,
                            DPoPConstants.INVALID_DPOP_ERROR);
                }
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_CLIENT, DPoPConstants.INVALID_CLIENT_ERROR);
        }
    }

    @Override
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig != null && Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {

        setDPoPTokenType(tokReqMsgCtx,tokenRespDTO);
    }

    /**
     * {@inheritdoc}
     */
    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) {
        setDPoPTokenType(tokReqMsgCtx,tokenRespDTO);

    }

    private void setDPoPTokenType(OAuthTokenReqMessageContext tokReqMsgCtx, OAuth2AccessTokenRespDTO tokenRespDTO) {

        if (tokReqMsgCtx.getTokenBinding() != null &&
                DPoPConstants.DPOP_TOKEN_TYPE.equals(tokReqMsgCtx.getTokenBinding().getBindingType())) {
            if (tokenRespDTO != null) {
                tokenRespDTO.setTokenType(DPoPConstants.DPOP_TOKEN_TYPE);
            }
        }
    }
}
