/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.introspection;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.CommonConstants;

import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for IntrospectionResponseInterceptorTest class.
 */
@PrepareForTest({IdentityUtil.class})
public class IntrospectionResponseInterceptorTest extends PowerMockTestCase {

    IntrospectionResponseInterceptor introspectionResponseInterceptor;

    @BeforeTest
    public void setup() {

        introspectionResponseInterceptor = new IntrospectionResponseInterceptor();
    }

    @Test
    public void testGetIntrospectionData() {

        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = new OAuth2IntrospectionResponseDTO();
        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO2 = new OAuth2IntrospectionResponseDTO();
        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO3 = new OAuth2IntrospectionResponseDTO();
        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO4 = new OAuth2IntrospectionResponseDTO();
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();

        Map<String, Object> introspectionData = new HashMap<String, Object>();
        introspectionData.put("nbf", 1585749816);
        introspectionData.put("active", true);
        introspectionData.put("iss", "https://server.example.com");
        introspectionData.put("exp", 1585753416);
        introspectionData.put("sub", "ty.webb@example.com");
        introspectionData.put("cnf", new String[]{"x5t#S256", "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"});

        oAuth2IntrospectionResponseDTO.setScope("openid");
        oAuth2IntrospectionResponseDTO.setProperties(introspectionData);
        oAuth2IntrospectionResponseDTO3.setScope("x5t#S256:bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2");
        oAuth2IntrospectionResponseDTO4.setScope("x5t#S256:bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2");

        introspectionResponseInterceptor.onPostTokenValidation(oAuth2TokenValidationRequestDTO,
                oAuth2IntrospectionResponseDTO, introspectionData);
        assertNotNull(oAuth2IntrospectionResponseDTO.getProperties());

        introspectionResponseInterceptor.onPostTokenValidation(oAuth2TokenValidationRequestDTO,
                oAuth2IntrospectionResponseDTO2, introspectionData);
        assertNotNull(oAuth2IntrospectionResponseDTO2.getProperties());

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(CommonConstants.ENABLE_TLS_CERT_TOKEN_BINDING)).thenReturn("true");

        introspectionResponseInterceptor.onPostTokenValidation(oAuth2TokenValidationRequestDTO,
                oAuth2IntrospectionResponseDTO3, introspectionData);
        assertNotNull(oAuth2IntrospectionResponseDTO3.getProperties());
        assertTrue(oAuth2IntrospectionResponseDTO3.getProperties().containsKey("cnf"));

        when(IdentityUtil.getProperty(CommonConstants.ENABLE_TLS_CERT_TOKEN_BINDING)).thenReturn("false");
        introspectionResponseInterceptor.onPostTokenValidation(oAuth2TokenValidationRequestDTO,
                oAuth2IntrospectionResponseDTO4, introspectionData);
        assertFalse(oAuth2IntrospectionResponseDTO4.getProperties().containsKey("cnf"));
    }
}
