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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core;

import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache.JWTConfigCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache.JWTConfigCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache.JWTConfigCacheKey;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.impl.CacheBackedJWTConfigurationDAOImpl;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.impl.JWTAuthenticationConfigurationDAOImpl;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.internal.JWTServiceDataHolder;

import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;

@WithCarbonHome
@WithKeyStore
public class JWTClientAuthenticatorMgtServiceTest {

    private JWTAuthenticationConfigurationDAOImpl jwtAuthenticationConfigurationDAO;

    private CacheBackedJWTConfigurationDAOImpl cacheBackedJWTConfigurationDAO;

    private ConfigurationManager mockConfigurationManager;

    private JWTClientAuthenticatorMgtService jwtClientAuthenticatorMgtService;


    @BeforeClass
    public void setUp() throws Exception {

        jwtAuthenticationConfigurationDAO = new JWTAuthenticationConfigurationDAOImpl();
        cacheBackedJWTConfigurationDAO = new CacheBackedJWTConfigurationDAOImpl(jwtAuthenticationConfigurationDAO);
        JWTServiceDataHolder.getInstance().setJWTAuthenticationConfigurationDAO(cacheBackedJWTConfigurationDAO);
        jwtClientAuthenticatorMgtService = new JWTClientAuthenticatorMgtServiceImpl();
        mockConfigurationManager = Mockito.mock(ConfigurationManager.class);
        JWTServiceDataHolder.getInstance()
                .setConfigurationManager(mockConfigurationManager);


    }

    @Test()
    private void testGetConfig() throws Exception {

        JWTConfigCacheKey jwtCacheKey = new JWTConfigCacheKey("sampleTenant");
        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
        jwtClientAuthenticatorConfig.setEnableTokenReuse(true);
        JWTConfigCacheEntry jwtConfigCacheEntry = new JWTConfigCacheEntry(jwtClientAuthenticatorConfig);

        JWTConfigCache.getInstance().addToCache(jwtCacheKey, jwtConfigCacheEntry);
        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig1 = JWTServiceDataHolder
                .getInstance().getPrivateKeyJWTAuthenticationConfigurationDAO()
                .getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain("sampleTenant");

        assertNotNull(jwtClientAuthenticatorConfig1);
        assertTrue(jwtClientAuthenticatorConfig1.isEnableTokenReuse());
    }
}
