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

package org.wso2.carbon.identity.dpop.token.binder;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.dao.DPoPTokenManagerDAO;
import org.wso2.carbon.identity.dpop.internal.DPoPDataHolder;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.dpop.validators.DPoPHeaderValidator;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.AbstractTokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class provides the DPoP based token binder implementation.
 */
public class DPoPBasedTokenBinder extends AbstractTokenBinder {

    private static final String BINDING_TYPE = "DPoP";
    private static final Log log = LogFactory.getLog(DPoPBasedTokenBinder.class);
    static Set<String> supportedGrantTypesSet = null;
    private DPoPTokenManagerDAO
            tokenBindingTypeManagerDao = DPoPDataHolder.getInstance().getTokenBindingTypeManagerDao();


    @Override
    public String getDisplayName() {

        return "DPoP Based";
    }

    @Override
    public String getDescription() {

        return "Bind tokens as DPoP tokens.";
    }

    @Override
    public String getBindingType() {

        return BINDING_TYPE;
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        return new ArrayList<>(Arrays.asList(getAllGrantTypes()));
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) {

        return null;
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue) {

        // Not required.
    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {

        // Not required.
    }

    @Override
    public boolean isValidTokenBinding(Object request, String bindingReference) {

        return true;
    }

    @Override
    public boolean isValidTokenBinding(Object request, TokenBinding tokenBinding) {

        try {
            if (tokenBinding != null && DPoPConstants.OAUTH_DPOP_HEADER.equals(tokenBinding.getBindingType())) {
                return validateDPoPHeader(request, tokenBinding);
            }
        } catch (IdentityOAuth2Exception | ParseException e) {
            log.error("Error while getting the token binding value", e);
            return false;
        }
        return false;
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        if (StringUtils.isBlank(bindingReference)) {
            return false;
        }

        String refreshToken = oAuth2AccessTokenReqDTO.getRefreshToken();
        try {
            TokenBinding tokenBinding =
                    tokenBindingTypeManagerDao.getTokenBinding(refreshToken, OAuth2Util.isHashEnabled());

            if (tokenBinding != null && DPoPConstants.OAUTH_DPOP_HEADER.equals(tokenBinding.getBindingType())) {
                return bindingReference.equalsIgnoreCase(tokenBinding.getBindingReference());
            }
            return false;
        } catch (IdentityOAuth2Exception e) {
            return false;
        }
    }

    @Override
    public String getTokenBindingValue(HttpServletRequest request) {

        try {
            String tokenBindingValue = retrieveTokenBindingValueFromDPoPHeader(request);

            if (StringUtils.isNotBlank(tokenBindingValue)) {
                return tokenBindingValue;
            }
            return null;
        } catch (IdentityOAuth2Exception e) {
            return null;
        }
    }

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        HttpRequestHeader[] httpRequestHeaders = oAuth2AccessTokenReqDTO.getHttpRequestHeaders();
        if (ArrayUtils.isEmpty(httpRequestHeaders)) {
            return Optional.empty();
        }
        for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
            if (DPoPConstants.OAUTH_DPOP_HEADER.equalsIgnoreCase(httpRequestHeader.getName())) {
                if (ArrayUtils.isEmpty(httpRequestHeader.getValue())) {
                    return Optional.empty();
                }

                String dpopProof = httpRequestHeader.getValue()[0];
                if (StringUtils.isEmpty(dpopProof)) {
                    return Optional.empty();
                }

                try {
                    String thumbprintOfPublicKey = Utils.getThumbprintOfKeyFromDpopProof(dpopProof);
                    return Optional.of(thumbprintOfPublicKey);
                } catch (IdentityOAuth2Exception e) {
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

    private String retrieveTokenBindingValueFromDPoPHeader(HttpServletRequest request) throws IdentityOAuth2Exception {

        String dpopProof = request.getHeader(DPoPConstants.OAUTH_DPOP_HEADER);
        if (StringUtils.isBlank(dpopProof)) {
            return null;
        }

        String thumbprintOfPublicKey = Utils.getThumbprintOfKeyFromDpopProof(dpopProof);
        if (StringUtils.isBlank(thumbprintOfPublicKey)) {
            return null;
        }
        return thumbprintOfPublicKey;
    }

    private boolean validateDPoPHeader(Object request, TokenBinding tokenBinding) throws IdentityOAuth2Exception,
            ParseException {

        if (!((HttpServletRequest) request).getHeader(DPoPConstants.AUTHORIZATION_HEADER)
                .startsWith(DPoPConstants.OAUTH_DPOP_HEADER)) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP prefix is not defined correctly in the Authorization header.");
            }
            return false;
        }

        String dpopHeader = ((HttpServletRequest) request).getHeader(DPoPConstants.OAUTH_DPOP_HEADER);

        if (StringUtils.isBlank(dpopHeader)) {
            if (log.isDebugEnabled()) {
                log.debug("DPoP header is empty.");
            }
            return false;

        }

        String httpMethod = (((HttpServletRequest) request).getMethod());
        String httpUrl = (((HttpServletRequest) request).getRequestURL().toString());
        if (!DPoPHeaderValidator.isValidDPoPProof(httpMethod, httpUrl, dpopHeader)) {
            return false;
        }

        String thumbprintOfPublicKey = Utils.getThumbprintOfKeyFromDpopProof(dpopHeader);

        if (StringUtils.isBlank(thumbprintOfPublicKey)) {
            if (log.isDebugEnabled()) {
                log.debug("Thumbprint value of the public key is empty in the DPoP Proof.");
            }
            return false;
        }

        if (!thumbprintOfPublicKey.equalsIgnoreCase(tokenBinding.getBindingValue())) {
            if (log.isDebugEnabled()) {
                log.debug("Thumbprint value of the public key in the DPoP proof is not equal to binding value" +
                        " of the responseDTO.");
            }
            return false;
        }
        return true;
    }

    public String[] getAllGrantTypes() {

        if (supportedGrantTypesSet == null) {
            synchronized (DPoPBasedTokenBinder.class) {
                if (supportedGrantTypesSet == null) {
                    supportedGrantTypesSet = OAuthServerConfiguration.getInstance().getSupportedGrantTypes().keySet();
                }
            }
        }
        return supportedGrantTypesSet.toArray(new String[supportedGrantTypesSet.size()]);
    }
}
