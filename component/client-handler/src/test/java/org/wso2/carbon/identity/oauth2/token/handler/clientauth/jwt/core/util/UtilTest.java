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

import org.apache.commons.lang.StringUtils;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;

import java.util.ArrayList;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.Constants.ENABLE_TOKEN_REUSE;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.constant.Constants.JWT_CONFIGURATION_RESOURCE_NAME;

public class UtilTest {

    @Test()
    public void testServerConfig() throws Exception {

        JWTServiceDataHolder.getInstance().setPreventTokenReuse(true);
        assertFalse(Util.getServerConfiguration().isEnableTokenReuse());
    }

    @Test()
    public void testResource() throws Exception {

        Resource resourceAdd = new Resource();
        resourceAdd.setResourceName(JWT_CONFIGURATION_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();
        addAttribute(attributes, ENABLE_TOKEN_REUSE,
                String.valueOf(true));
        resourceAdd.setAttributes(attributes);
        resourceAdd.setHasAttribute(true);

        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = Util.parseResource(resourceAdd);
        assertNotNull(jwtClientAuthenticatorConfig);
        assertTrue(jwtClientAuthenticatorConfig.isEnableTokenReuse());
    }

    private void addAttribute(List<Attribute> attributeList, String key, String value) {

        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(key);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }

    @Test()
    public void testConfig() throws Exception {

        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
        jwtClientAuthenticatorConfig.setEnableTokenReuse(true);
        ResourceAdd resourceAdd = Util.parseConfig(jwtClientAuthenticatorConfig);
        assertEquals(resourceAdd.getAttributes().get(0).getKey(), ENABLE_TOKEN_REUSE);
        assertTrue(Boolean.parseBoolean(resourceAdd.getAttributes().get(0).getValue()));
    }
}
