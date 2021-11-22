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
                    authorizationHeader.startsWith(DPoPConstants.OAUTH_DPOP_HEADER)) {
                String accessToken;
                String[] dpopToken = authorizationHeader.split(" ");
                if (dpopToken.length != 2) {
                    String errorMessage = String.format("Error occurred while trying to authenticate." +
                            "The %s header value is not defined correctly.", DPoPConstants.OAUTH_DPOP_HEADER);
                    throw new AuthenticationFailException(errorMessage);
                }
                accessToken = dpopToken[1];
                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                token.setIdentifier(accessToken);
                token.setTokenType(DPoPConstants.OAUTH_DPOP_HEADER);
                requestDTO.setAccessToken(token);
                setContextParam(authenticationRequest, requestDTO);
                OAuth2ClientApplicationDTO clientApplicationDTO =
                        oAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(requestDTO);
                OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();
                if (!responseDTO.isValid()) {
                    if (log.isDebugEnabled()) {
                        log.debug(responseDTO.getErrorMsg());
                    }
                    return authenticationResult;
                }
                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                return authenticationResult;
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

    private void setContextParam(AuthenticationRequest authenticationRequest,
                                 OAuth2TokenValidationRequestDTO requestDTO) {

        HttpServletRequest request = authenticationRequest.getRequest();
        String dpopHeader = request.getHeader(DPoPConstants.OAUTH_DPOP_HEADER);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam httpMethod = requestDTO.new
                TokenValidationContextParam();
        httpMethod.setKey(DPoPConstants.HTTP_METHOD);
        httpMethod.setValue(request.getMethod());

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam httpURL = requestDTO.new
                TokenValidationContextParam();
        httpURL.setKey(DPoPConstants.HTTP_URL);
        httpURL.setValue(String.valueOf(request.getRequestURL()));

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam dpopProof = requestDTO.new
                TokenValidationContextParam();
        dpopProof.setKey(DPoPConstants.OAUTH_DPOP_HEADER);
        dpopProof.setValue(dpopHeader);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams =
                new OAuth2TokenValidationRequestDTO.TokenValidationContextParam[3];
        contextParams[0] = httpMethod;
        contextParams[1] = httpURL;
        contextParams[2] = dpopProof;
        requestDTO.setContext(contextParams);
    }
}
