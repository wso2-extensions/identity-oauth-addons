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

package org.wso2.carbon.identity.dpop.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.token.binder.DPoPBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import javax.servlet.http.HttpServletRequest;

/**
 * DPoPAuthenticationHandler will validate the requests authorized with DPoP access tokens.
 */
public class DPoPAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(DPoPAuthenticationHandler.class);

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws
            AuthenticationFailException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        if (authenticationRequest != null) {

            String authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.isNotBlank(authorizationHeader) &&
                    authorizationHeader.startsWith(DPoPConstants.OAUTH_DPOP_HEADER) ) {
                String accessToken;
                String[] dpopToken = authorizationHeader.split(" ");
                if (dpopToken.length != 2) {
                    String errorMessage = String.format("Error occurred while trying to authenticate." +
                            "The %s header value is not defined correctly.", DPoPConstants.OAUTH_DPOP_HEADER);
                    log.error(errorMessage);
                    throw new AuthenticationFailException(errorMessage);
                }
                accessToken = dpopToken[1];
                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                token.setIdentifier(accessToken);
                token.setTokenType(DPoPConstants.OAUTH_DPOP_HEADER);
                requestDTO.setAccessToken(token);

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                        TokenValidationContextParam();

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = { contextParam };
                requestDTO.setContext(contextParams);

                OAuth2ClientApplicationDTO clientApplicationDTO =
                        oAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(requestDTO);
                OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();

                validateDPoPHeaderandToken(authenticationResult,responseDTO, authenticationRequest);

            }
        }
        return authenticationResult;
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 24);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        return AuthConfigurationUtil.isAuthHeaderMatch(messageContext, DPoPConstants.OAUTH_DPOP_HEADER);
    }

    public static AuthenticationResult validateDPoPHeaderandToken(AuthenticationResult authenticationResult,
                                                                  OAuth2TokenValidationResponseDTO responseDTO,
                                                                  AuthenticationRequest authenticationRequest) {

        if (!responseDTO.isValid()) {
            log.debug(responseDTO.getErrorMsg());
            return authenticationResult;
        }
        DPoPBasedTokenBinder dPoPBasedTokenBinder = new DPoPBasedTokenBinder();
        HttpServletRequest request = authenticationRequest.getRequest();
        if (dPoPBasedTokenBinder.isValidTokenBinding(request, responseDTO.getTokenBinding())) {
            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
        }
        return authenticationResult;
    }
}
