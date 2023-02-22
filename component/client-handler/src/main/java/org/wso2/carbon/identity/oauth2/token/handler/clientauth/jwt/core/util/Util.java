/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.Constants.ENABLE_TOKEN_REUSE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.Constants.JWT_CONFIGURATION_RESOURCE_NAME;

/**
 * Util class.
 */
public class Util {

    /**
     * Read the default JWT Authenticator configuration properties from the Data Holder..
     *
     * @return Server default {@code JWTClientAuthenticatorConfig} object.
     */
    public static JWTClientAuthenticatorConfig getServerConfiguration() {

        JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();

        JWTClientAuthenticatorConfig.
                setEnableTokenReuse(!JWTServiceDataHolder.getInstance().isPreventTokenReuse());
        return JWTClientAuthenticatorConfig;
    }

    /**
     * Parse Resource to JWTClientAuthenticatorConfig instance.
     *
     * @param resource Resource
     * @return JWTClientAuthenticatorConfig Configuration instance.
     */
    public static JWTClientAuthenticatorConfig parseResource(Resource resource) {

        JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();

        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);
            JWTClientAuthenticatorConfig.setEnableTokenReuse(
                    Boolean.parseBoolean(attributeMap.get(ENABLE_TOKEN_REUSE)));
        }
        return JWTClientAuthenticatorConfig;

    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }

        return Collections.emptyMap();
    }

    /**
     * Parse JWTClientAuthenticatorConfig to Resource instance.
     *
     * @param jwtClientAuthenticatorConfig Configuration Instance.
     * @return ResourceAdd Resource instance.
     */
    public static ResourceAdd parseConfig(JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(JWT_CONFIGURATION_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();
        addAttribute(attributes, jwtClientAuthenticatorConfig);
        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }

    private static void addAttribute(List<Attribute> attributeList,
                                     JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig) {

        String value = String.valueOf(jwtClientAuthenticatorConfig.isEnableTokenReuse());
        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(ENABLE_TOKEN_REUSE);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }
}
