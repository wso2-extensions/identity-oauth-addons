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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.dpop.validators.DPoPValidator;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.AbstractTokenBinder;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class provides the DPoP based token binder implementation.
 */
public class DPoPBasedTokenBinder extends AbstractTokenBinder {

    private static final String BINDING_TYPE = "DPoP";
    private static Optional<String> tokenBindingValue;
    private final List<String> supportedGrantTypes = Arrays.asList(GrantTypes.AUTHORIZATION_CODE, GrantTypes.PASSWORD,
            GrantTypes.CLIENT_CREDENTIALS, GrantTypes.REFRESH_TOKEN);
    private static final Log log = LogFactory.getLog(DPoPBasedTokenBinder.class);

    public static void setTokenBindingValue(String bindingValue) {

        tokenBindingValue = Optional.ofNullable(bindingValue);
    }

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

        return Collections.unmodifiableList(supportedGrantTypes);
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        return null;
    }

    @Override
    public String getTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        return super.getTokenBindingValue(request);
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
        return true;
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        return true;
    }

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        return tokenBindingValue;
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
            if (StringUtils.isBlank(dpopHeader)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP header is empty.");
                }
                return false;
            }
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

        return DPoPValidator.isValidDPoP(request, dpopHeader);
    }
}
