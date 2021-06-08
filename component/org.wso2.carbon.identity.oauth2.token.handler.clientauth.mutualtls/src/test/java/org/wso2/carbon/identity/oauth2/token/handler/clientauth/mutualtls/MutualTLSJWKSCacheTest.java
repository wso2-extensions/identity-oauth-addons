/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls;

import com.nimbusds.jose.util.Resource;
import org.testng.IObjectFactory;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCacheKey;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for MutualTLSJWKSCache class.
 */
@WithCarbonHome
@WithRealmService
public class MutualTLSJWKSCacheTest {


    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Test
    public void testCachePut() throws Exception {
        Resource testResource = new Resource("content", "type");
        MutualTLSJWKSCacheKey mutualTLSJWKSCacheKey = new MutualTLSJWKSCacheKey("jwksUri");
        MutualTLSJWKSCache.getInstance().addToCache(mutualTLSJWKSCacheKey, new MutualTLSJWKSCacheEntry(testResource));
        MutualTLSJWKSCacheEntry mutualTLSJWKSCacheEntry = MutualTLSJWKSCache.getInstance()
                .getValueFromCache(mutualTLSJWKSCacheKey);
        Resource fetchedResource = mutualTLSJWKSCacheEntry.getValue();
        assertEquals(fetchedResource.getContent(), testResource.getContent());

    }
}
