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

package org.wso2.carbon.identity.dpop.introspection.dataprovider;

import org.json.simple.JSONObject;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IntrospectionDataProvider;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.HashMap;
import java.util.Map;

/**
 * Introspection Data provider to include cnf  to introspection response.
 */
public class DPoPIntrospectionDataProvider extends AbstractIdentityHandler implements IntrospectionDataProvider {

    @Override
    public Map<String, Object> getIntrospectionData(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                                    OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO)
            throws IdentityOAuth2Exception {

        Map<String, Object> introspectionData = new HashMap<>();
        AccessTokenDO accessTokenDO;

        if (isEnabled()) {

            accessTokenDO = OAuth2Util.findAccessToken(oAuth2TokenValidationRequestDTO.
                    getAccessToken().getIdentifier(), false);

            if (accessTokenDO.getTokenBinding() != null &&
                    DPoPConstants.DPOP_TOKEN_TYPE.equals(accessTokenDO.getTokenBinding().getBindingType())) {
                introspectionData.put(DPoPConstants.TOKEN_TYPE, (DPoPConstants.DPOP_TOKEN_TYPE));
                JSONObject cnf = new JSONObject();
                cnf.put(DPoPConstants.JWK_THUMBPRINT, accessTokenDO.getTokenBinding().getBindingValue());
                introspectionData.put(DPoPConstants.CNF, cnf);
            }
        }
        return introspectionData;
    }
}
