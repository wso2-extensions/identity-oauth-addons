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

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.AbstractTokenBinder;

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
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        return true;
    }

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        return tokenBindingValue;
    }
}
