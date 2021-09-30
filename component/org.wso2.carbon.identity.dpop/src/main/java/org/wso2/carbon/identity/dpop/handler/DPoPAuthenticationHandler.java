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

import org.apache.catalina.connector.Request;
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
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

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
                    authorizationHeader.startsWith(DPoPConstants.OAUTH_DPOP_HEADER) ||
                    (authorizationHeader.startsWith(DPoPConstants.OAUTH_HEADER))) {
                String accessToken;
                String[] bearerToken = authorizationHeader.split(" ");
                if (bearerToken.length == 2) {
                    accessToken = bearerToken[1];
                    OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                    OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                    OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                    token.setIdentifier(accessToken);
                    token.setTokenType(DPoPConstants.OAUTH_HEADER);
                    requestDTO.setAccessToken(token);

                    OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                            TokenValidationContextParam();

                    OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = { contextParam };
                    requestDTO.setContext(contextParams);

                    OAuth2ClientApplicationDTO clientApplicationDTO =
                            oAuth2TokenValidationService.findOAuthConsumerIfTokenIsValid(requestDTO);
                    OAuth2TokenValidationResponseDTO responseDTO =
                            clientApplicationDTO.getAccessTokenValidationResponse();

                    String consumerKey = clientApplicationDTO.getConsumerKey();

                    getAuthenticationResult(authenticationResult, responseDTO, authorizationHeader,
                            authenticationRequest, messageContext, accessToken, consumerKey);

                    setAuthenticationContext(responseDTO, authenticationContext, consumerKey);

                    String serviceProvider;
                    try {
                        serviceProvider =
                                OAuth2Util.getServiceProvider(consumerKey).getApplicationName();
                    } catch (IdentityOAuth2Exception e) {
                        String error = String.format("Error occurred while getting the Service Provider" +
                                " by Consumer key: %s.", consumerKey);
                        log.error(error, e);
                        throw new AuthenticationFailException(error);
                    }

                    String serviceProviderTenantDomain;
                    try {
                        serviceProviderTenantDomain =
                                OAuth2Util.getTenantDomainOfOauthApp(consumerKey);
                    } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {

                        String error = String.format("Error occurred while getting the OAuth App" +
                                " tenantDomain by Consumer key: %s.", consumerKey);
                        log.error(error, e);
                        throw new AuthenticationFailException(error);
                    }

                    authenticationContext.addParameter(DPoPConstants.SERVICE_PROVIDER, serviceProvider);
                    authenticationContext.addParameter(DPoPConstants.SERVICE_PROVIDER_TENANT_DOMAIN,
                            serviceProviderTenantDomain);

                    MDC.put(DPoPConstants.SERVICE_PROVIDER, serviceProvider);
                    // Set OAuth service provider details to be consumed by the provisioning framework.
                    setProvisioningServiceProviderThreadLocal(clientApplicationDTO.getConsumerKey(),
                            serviceProviderTenantDomain);

                } else {
                    String errorMessage = String.format("Error occurred while trying to authenticate." +
                            "The %s header value is not defined correctly.", DPoPConstants.OAUTH_DPOP_HEADER);
                    log.error(errorMessage);
                    throw new AuthenticationFailException(errorMessage);
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

        return AuthConfigurationUtil.isAuthHeaderMatch(messageContext, DPoPConstants.OAUTH_DPOP_HEADER) ||
                AuthConfigurationUtil.isAuthHeaderMatch(messageContext, DPoPConstants.OAUTH_HEADER);
    }

    private AuthenticationResult getAuthenticationResult(AuthenticationResult authenticationResult,
                                                         OAuth2TokenValidationResponseDTO responseDTO,
                                                         String authorizationHeader,
                                                         AuthenticationRequest authenticationRequest,
                                                         MessageContext messageContext, String accessToken,
                                                         String consumerKey)
            throws AuthenticationFailException {

        if (!responseDTO.isValid()) {
            log.debug(responseDTO.getErrorMsg());
            return authenticationResult;
        }

        TokenBinding binding = responseDTO.getTokenBinding();
        if (binding != null && DPoPConstants.OAUTH_DPOP_HEADER.equals(binding.getBindingType())) {
            if (!authorizationHeader.startsWith(DPoPConstants.OAUTH_DPOP_HEADER)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP prefix is not defined correctly in the Authorization header.");
                }
                return authenticationResult;
            }
            String dpopHeader = authenticationRequest.getHeader(DPoPConstants.OAUTH_DPOP_HEADER);

            if (StringUtils.isBlank(dpopHeader)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP header is empty.");
                }
                return authenticationResult;
            }
            try {
                String thumbprintOfPublicKey = Utils.getThumbprintOfKeyFromDpopProof(dpopHeader);
                if (StringUtils.isBlank(thumbprintOfPublicKey)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Thumbprint value of the public key is empty in the DPoP Proof.");
                    }
                    return authenticationResult;
                }
                if (!thumbprintOfPublicKey.equalsIgnoreCase(responseDTO.getTokenBinding().getBindingValue())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Thumbprint value of the public key in the DPoP proof is not equal to binding value" +
                                " of the responseDTO.");
                    }
                    return authenticationResult;
                }
            } catch (IdentityOAuth2Exception e) {
                String errorMessage = "Error occurred while getting the thumbprint of the public key from the DPoP " +
                        "proof.";
                throw new AuthenticationFailException(errorMessage);
            }
        } else {
            if (!authorizationHeader.startsWith(DPoPConstants.OAUTH_HEADER)) {
                return authenticationResult;
            }

            if (!isTokenBindingValid(messageContext, binding,
                    consumerKey, accessToken)) {
                return authenticationResult;
            }
        }
        authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
        return authenticationResult;
    }

    /**
     * Validate access token binding value.
     *
     * @param messageContext message context.
     * @param tokenBinding   token binding.
     * @param clientId       OAuth2 client id.
     * @param accessToken    Bearer token from request.
     * @return true if token binding is valid.
     */
    private boolean isTokenBindingValid(MessageContext messageContext, TokenBinding tokenBinding, String clientId,
                                        String accessToken) {

        if (tokenBinding == null || StringUtils.isBlank(tokenBinding.getBindingReference())) {
            return true;
        }

        Request authenticationRequest =
                ((AuthenticationContext) messageContext).getAuthenticationRequest().getRequest();
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Failed to retrieve application information by client id: " + clientId, e);
            return false;
        }

        if (!oAuthAppDO.isTokenBindingValidationEnabled()) {
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(DPoPConstants.SCIM2_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(getTokenBindingValueFromAccessToken(accessToken));
            }
            return true;
        }

        if (OAuth2Util.isValidTokenBinding(tokenBinding, authenticationRequest)) {
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(DPoPConstants.SCIM2_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(tokenBinding.getBindingValue());
            }
            return true;
        }
        return false;
    }

    /**
     * Get the token binding value which corresponds to the current session identifier from the token when
     * SSO-session-based token binding is enabled.
     *
     * @param accessToken Bearer token from request.
     * @return Token binding value.
     */
    private String getTokenBindingValueFromAccessToken(String accessToken) {

        String tokenBindingValue = null;
        try {
            AccessTokenDO accessTokenDO = OAuth2Util.findAccessToken(accessToken, false);
            if (accessTokenDO != null) {
                if (accessTokenDO.getTokenBinding() != null &&
                        StringUtils.isNotBlank(accessTokenDO.getTokenBinding().getBindingValue()) &&
                        isSSOSessionBasedTokenBinding(accessTokenDO.getTokenBinding().getBindingType())) {
                    tokenBindingValue = accessTokenDO.getTokenBinding().getBindingValue();
                }
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while getting the access token from the token identifier", e);
        }
        return tokenBindingValue;
    }

    /**
     * Set token binding value which corresponds to the current session id to a thread local to be used down the flow.
     *
     * @param tokenBindingValue Token Binding value.
     */
    private void setCurrentSessionIdThreadLocal(String tokenBindingValue) {

        if (StringUtils.isNotBlank(tokenBindingValue)) {
            IdentityUtil.threadLocalProperties.get().put(Constants.CURRENT_SESSION_IDENTIFIER, tokenBindingValue);
            if (log.isDebugEnabled()) {
                log.debug("Current session identifier: " + tokenBindingValue + " is added to thread local.");
            }
        }
    }

    /**
     * Check whether the token binding type is 'sso-session'.
     *
     * @param tokenBindingType Type of the token binding.
     * @return True if 'sso-session', false otherwise.
     */
    private boolean isSSOSessionBasedTokenBinding(String tokenBindingType) {

        return TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER.equals(tokenBindingType);
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
