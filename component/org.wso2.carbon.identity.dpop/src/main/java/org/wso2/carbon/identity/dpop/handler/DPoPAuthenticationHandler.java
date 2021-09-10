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
import org.slf4j.MDC;
import org.wso2.carbon.identity.application.common.model.ProvisioningServiceProviderType;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * DPoPAuthenticationHandler is for authenticate the request based on Token.
 */
public class DPoPAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(DPoPAuthenticationHandler.class);

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        if (authenticationRequest != null) {

            String authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.isNotBlank(authorizationHeader) &&
                    authorizationHeader.startsWith(DPoPConstants.OAUTH_DPOP_HEADER)) {
                String accessToken = null;
                String[] bearerToken = authorizationHeader.split(" ");
                if (bearerToken.length == 2) {
                    accessToken = bearerToken[1];
                }

                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                token.setIdentifier(accessToken);
                token.setTokenType(DPoPConstants.OAUTH_HEADER);
                requestDTO.setAccessToken(token);

                //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
                OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                        TokenValidationContextParam();
                contextParam.setKey("dummy");
                contextParam.setValue("dummy");

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = { contextParam };
                requestDTO.setContext(contextParams);

                OAuth2ClientApplicationDTO clientApplicationDTO =
                        oAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(requestDTO);
                OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();

                getAuthenticationResult(authenticationResult, responseDTO, authorizationHeader, authenticationRequest);

                String consumerKey = clientApplicationDTO.getConsumerKey();

                setAuthenticationContext(responseDTO, authenticationContext, consumerKey);

                String serviceProvider = null;
                try {
                    serviceProvider =
                            OAuth2Util.getServiceProvider(consumerKey).getApplicationName();
                } catch (IdentityOAuth2Exception e) {
                    String error = String.format("Error occurred while getting the Service Provider" +
                            " by Consumer key: %s.", consumerKey);
                    log.error(error, e);
                }

                String serviceProviderTenantDomain = null;
                try {
                    serviceProviderTenantDomain =
                            OAuth2Util.getTenantDomainOfOauthApp(consumerKey);
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {

                    String error = String.format("Error occurred while getting the OAuth App" +
                            " tenantDomain by Consumer key: %s.", consumerKey);
                    log.error(error, e);
                }

                if (serviceProvider != null) {
                    authenticationContext.addParameter(DPoPConstants.SERVICE_PROVIDER, serviceProvider);
                    if (serviceProviderTenantDomain != null) {
                        authenticationContext.addParameter(DPoPConstants.SERVICE_PROVIDER_TENANT_DOMAIN,
                                serviceProviderTenantDomain);
                    }

                    MDC.put(DPoPConstants.SERVICE_PROVIDER, serviceProvider);
                    // Set OAuth service provider details to be consumed by the provisioning framework.
                    setProvisioningServiceProviderThreadLocal(clientApplicationDTO.getConsumerKey(),
                            serviceProviderTenantDomain);
                }
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

    private AuthenticationResult getAuthenticationResult(AuthenticationResult authenticationResult,
                                                         OAuth2TokenValidationResponseDTO responseDTO,
                                                         String authorizationHeader,
                                                         AuthenticationRequest authenticationRequest) {

        if (!responseDTO.isValid()) {
            return authenticationResult;
        }

        TokenBinding binding = responseDTO.getTokenBinding();
        if (DPoPConstants.OAUTH_DPOP_HEADER.equals(binding.getBindingType())) {
            if (!authorizationHeader.startsWith(DPoPConstants.OAUTH_DPOP_HEADER)) {
                return authenticationResult;
            }
            String dpopHeader = authenticationRequest.getHeader(DPoPConstants.OAUTH_DPOP_HEADER);

            if (StringUtils.isBlank(dpopHeader)) {
                return authenticationResult;
            }
            try {
                String thumbprintOfPublicKey = Utils.getThumbprintOfKeyFromDpopProof(dpopHeader);
                if (StringUtils.isBlank(thumbprintOfPublicKey) ||
                        !thumbprintOfPublicKey
                                .equalsIgnoreCase(responseDTO.getTokenBinding().getBindingValue())) {
                    return authenticationResult;
                }
            } catch (IdentityOAuth2Exception e) {
                return authenticationResult;
            }
        }
        authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
        return authenticationResult;
    }

    private void setAuthenticationContext(OAuth2TokenValidationResponseDTO responseDTO,
                                          AuthenticationContext authenticationContext, String consumerKey) {

        if (StringUtils.isNotEmpty(responseDTO.getAuthorizedUser())) {
            User user = new User();
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(responseDTO.getAuthorizedUser());
            user.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUsername));
            user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(tenantAwareUsername));
            user.setTenantDomain(MultitenantUtils.getTenantDomain(responseDTO.getAuthorizedUser()));
            authenticationContext.setUser(user);
        }

        authenticationContext.addParameter(DPoPConstants.CONSUMER_KEY, consumerKey);
        authenticationContext.addParameter(Constants.OAUTH2_ALLOWED_SCOPES, responseDTO.getScope());
        authenticationContext.addParameter(Constants.OAUTH2_VALIDATE_SCOPE,
                AuthConfigurationUtil.getInstance().isScopeValidationEnabled());
    }

    private void setProvisioningServiceProviderThreadLocal(String oauthAppConsumerKey,
                                                           String serviceProviderTenantDomain) {

        if (serviceProviderTenantDomain != null) {
            ThreadLocalProvisioningServiceProvider provisioningServiceProvider =
                    new ThreadLocalProvisioningServiceProvider();
            provisioningServiceProvider.setServiceProviderName(oauthAppConsumerKey);
            provisioningServiceProvider.setServiceProviderType(ProvisioningServiceProviderType.OAUTH);
            provisioningServiceProvider.setTenantDomain(serviceProviderTenantDomain);
            IdentityApplicationManagementUtil.setThreadLocalProvisioningServiceProvider(provisioningServiceProvider);
        }
    }
}
