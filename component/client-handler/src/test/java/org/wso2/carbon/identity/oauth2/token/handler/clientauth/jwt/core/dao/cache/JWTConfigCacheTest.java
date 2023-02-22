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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithKeyStore;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

@WithCarbonHome
@WithKeyStore
public class JWTConfigCacheTest {

    private JWTConfigCache jwtConfigCache;
    private JWTConfigCacheKey jwtCacheKey;

    private JWTConfigCacheEntry jwtConfigCacheEntry;

    @BeforeClass
    public void setUp() throws Exception {

        jwtConfigCache = JWTConfigCache.getInstance();
        jwtCacheKey = new JWTConfigCacheKey("sampleTenant");
        JWTClientAuthenticatorConfig jwtClientAuthenticatorConfig = new JWTClientAuthenticatorConfig();
        jwtClientAuthenticatorConfig.setEnableTokenReuse(true);
        jwtConfigCacheEntry = new JWTConfigCacheEntry(jwtClientAuthenticatorConfig);
    }

    @Test()
    public void testCache() throws Exception {

        assertNotNull(jwtConfigCache);
    }

    @Test()
    public void testAddToCache() throws Exception {
        jwtConfigCache.addToCache(jwtCacheKey, jwtConfigCacheEntry);

    }

    @Test(dependsOnMethods = {"testAddToCache"})
    public void testGetValueFromCache() throws Exception {
        assertEquals(jwtConfigCache.getValueFromCache(jwtCacheKey), jwtConfigCacheEntry);
    }

    @Test(dependsOnMethods = {"testGetValueFromCache"})
    public void testClearCacheEntry() throws Exception {
        jwtConfigCache.clearCacheEntry(jwtCacheKey);
        assertNull(jwtConfigCache.getValueFromCache(jwtCacheKey));

    }
}
