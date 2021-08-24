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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
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
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.dpop.constant.Constants.CONSUMER_KEY;
import static org.wso2.carbon.identity.dpop.constant.Constants.ECDSA_ENCRYPTION;
import static org.wso2.carbon.identity.dpop.constant.Constants.OAUTH_DPOP_HEADER;
import static org.wso2.carbon.identity.dpop.constant.Constants.OAUTH_HEADER;
import static org.wso2.carbon.identity.dpop.constant.Constants.RSA_ENCRYPTION;
import static org.wso2.carbon.identity.dpop.constant.Constants.SCIM_ME_ENDPOINT_URI;
import static org.wso2.carbon.identity.dpop.constant.Constants.SERVICE_PROVIDER;
import static org.wso2.carbon.identity.dpop.constant.Constants.SERVICE_PROVIDER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER;

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
            if (StringUtils.isNotEmpty(authorizationHeader) && (authorizationHeader.startsWith(OAUTH_HEADER) ||
                    authorizationHeader.startsWith(OAUTH_DPOP_HEADER))) {
                String accessToken = null;
                String[] bearerToken = authorizationHeader.split(" ");
                if (bearerToken.length == 2) {
                    accessToken = bearerToken[1];
                }

                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                token.setIdentifier(accessToken);
                token.setTokenType(OAUTH_HEADER);
                requestDTO.setAccessToken(token);

                //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
                OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                        TokenValidationContextParam();
                contextParam.setKey("dummy");
                contextParam.setValue("dummy");

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams =
                        new OAuth2TokenValidationRequestDTO.TokenValidationContextParam[1];
                contextParams[0] = contextParam;
                requestDTO.setContext(contextParams);

                OAuth2ClientApplicationDTO clientApplicationDTO = oAuth2TokenValidationService
                        .findOAuthConsumerIfTokenIsValid
                                (requestDTO);
                OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();

                if (!responseDTO.isValid()) {
                    return authenticationResult;
                }

                TokenBinding binding = responseDTO.getTokenBinding();
                if (binding != null && binding.getBindingType().contains(OAUTH_DPOP_HEADER)) {
                    if (!authorizationHeader.startsWith(OAUTH_DPOP_HEADER)) {
                        return authenticationResult;
                    }
                    String dpopHeader = ((AuthenticationContext) messageContext).getAuthenticationRequest()
                            .getHeader(OAUTH_DPOP_HEADER);
                    if (StringUtils.isBlank(dpopHeader)) {
                        return authenticationResult;
                    }
                    try {
                        String publicKey = getPublicKeyFromDpopProof(dpopHeader);
                        if (StringUtils.isBlank(publicKey) ||
                                !publicKey.equalsIgnoreCase(responseDTO.getTokenBinding().getBindingValue())) {
                            return authenticationResult;
                        }
                    } catch (IdentityOAuth2Exception e) {
                        return authenticationResult;
                    }
                } else {
                    if (!authorizationHeader.startsWith(OAUTH_HEADER)) {
                        return authenticationResult;
                    }
                }

                if (!isTokenBindingValid(messageContext, binding,
                        clientApplicationDTO.getConsumerKey(), accessToken)) {
                    return authenticationResult;
                }

                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);

                if (StringUtils.isNotEmpty(responseDTO.getAuthorizedUser())) {
                    User user = new User();
                    String tenantAwareUsername =
                            MultitenantUtils.getTenantAwareUsername(responseDTO.getAuthorizedUser());
                    user.setUserName(UserCoreUtil.removeDomainFromName(tenantAwareUsername));
                    user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(tenantAwareUsername));
                    user.setTenantDomain(MultitenantUtils.getTenantDomain(responseDTO.getAuthorizedUser()));
                    authenticationContext.setUser(user);
                }

                authenticationContext.addParameter(CONSUMER_KEY, clientApplicationDTO.getConsumerKey());
                authenticationContext.addParameter(OAUTH2_ALLOWED_SCOPES, responseDTO.getScope());
                authenticationContext.addParameter(OAUTH2_VALIDATE_SCOPE,
                        AuthConfigurationUtil.getInstance().isScopeValidationEnabled());
                String serviceProvider = null;
                try {
                    serviceProvider =
                            OAuth2Util.getServiceProvider(clientApplicationDTO.getConsumerKey()).getApplicationName();
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error occurred while getting the Service Provider by Consumer key: "
                            + clientApplicationDTO.getConsumerKey());
                }

                String serviceProviderTenantDomain = null;
                try {
                    serviceProviderTenantDomain =
                            OAuth2Util.getTenantDomainOfOauthApp(clientApplicationDTO.getConsumerKey());
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                    log.error("Error occurred while getting the OAuth App tenantDomain by Consumer key: "
                            + clientApplicationDTO.getConsumerKey());
                }

                if (serviceProvider != null) {
                    authenticationContext.addParameter(SERVICE_PROVIDER, serviceProvider);
                    if (serviceProviderTenantDomain != null) {
                        authenticationContext.addParameter(SERVICE_PROVIDER_TENANT_DOMAIN, serviceProviderTenantDomain);
                    }

                    MDC.put(SERVICE_PROVIDER, serviceProvider);
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

        return isAuthHeaderMatch(messageContext, OAUTH_HEADER) || isAuthHeaderMatch(messageContext, "DPoP");
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
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(getTokenBindingValueFromAccessToken(accessToken));
            }
            return true;
        }

        if (OAuth2Util.isValidTokenBinding(tokenBinding, authenticationRequest)) {
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI) &&
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

                if (accessTokenDO != null && accessTokenDO.getTokenBinding() != null &&
                        StringUtils.isNotBlank(accessTokenDO.getTokenBinding().getBindingValue()) &&
                        isSSOSessionBasedTokenBinding(accessTokenDO.getTokenBinding().getBindingType())) {
                    tokenBindingValue = accessTokenDO.getTokenBinding().getBindingValue();
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

        return SSO_SESSION_BASED_TOKEN_BINDER.equals(tokenBindingType);
    }

    /**
     * Set the service provider details to a thread local variable to be consumed by the provisioning framework.
     *
     * @param oauthAppConsumerKey         Client ID of the OAuth client application.
     * @param serviceProviderTenantDomain Tenant Domain of the OAuth application.
     */
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

    private String getPublicKeyFromDpopProof(String dPopProof)
            throws IdentityOAuth2Exception {

        try {
            SignedJWT signedJwt = SignedJWT.parse(dPopProof);
            JWSHeader header = signedJwt.getHeader();

            return getKeyThumbprintOfKey(header.getJWK().toString(), signedJwt);

        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Invalid DPoP Header");
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(e.getMessage());
        }
    }

    private String getKeyThumbprintOfKey(String jwk, SignedJWT signedJwt)
            throws ParseException, JOSEException {

        JWK parseJwk = JWK.parse(jwk);
        boolean validSignature;
        if (ECDSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            ECKey ecKey = (ECKey) parseJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            validSignature = verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey), signedJwt);
            if (validSignature) {
                return computeThumbprintOfECKey(ecKey);
            }
        } else if (RSA_ENCRYPTION.equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            RSAKey rsaKey = (RSAKey) parseJwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            validSignature = verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey), signedJwt);
            if (validSignature) {
                return computeThumbprintOfRSAKey(rsaKey);
            }
        }
        return null;
    }

    private String computeThumbprintOfRSAKey(RSAKey rsaKey) throws JOSEException {

        return rsaKey.computeThumbprint().toString();
    }

    private String computeThumbprintOfECKey(ECKey ecKey) throws JOSEException {

        return ecKey.computeThumbprint().toString();

    }

    private boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt) throws JOSEException {

        return signedJwt.verify(jwsVerifier);
    }
}
