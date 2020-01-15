
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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.cache.MutualTLSJWKSCacheKey;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertEquals;

/**
 * Test class for MutualTLSJWKSCacheKey class.
 */
public class MutualTLSJWKSCacheKeyTest {

    String cacheKeyString = "cacheKey1";
    Integer cacheKeyStringHashCode = cacheKeyString.hashCode();

    @Test
    public void testGetCacheKeyString() throws Exception {

        MutualTLSJWKSCacheKey mutualTLSJWKSCacheKey = new MutualTLSJWKSCacheKey(cacheKeyString);
        assertEquals(mutualTLSJWKSCacheKey.getJWKSCacheKey(), cacheKeyString, "Get MutualTLSJWKSCacheKey failed");
    }

    @Test
    public void testEqualsWhenCacheKeyEqual() throws Exception {

        MutualTLSJWKSCacheKey mutualTLSJWKSCacheKey = new MutualTLSJWKSCacheKey(cacheKeyString);
        MutualTLSJWKSCacheKey mutualTLSJWKSCacheKeySample = new MutualTLSJWKSCacheKey(cacheKeyString);
        assertTrue(mutualTLSJWKSCacheKey.equals(mutualTLSJWKSCacheKeySample));
    }

    @Test
    public void testNotEquals() throws Exception {

        Object object = new Object();
        MutualTLSJWKSCacheKey mutualTLSJWKSCacheKey = new MutualTLSJWKSCacheKey(cacheKeyString);
        assertFalse(mutualTLSJWKSCacheKey.equals(object));
    }

    @Test
    public void testHashCode() throws Exception {

        MutualTLSJWKSCacheKey mutualTLSJWKSCacheKey = new MutualTLSJWKSCacheKey(cacheKeyString);
        Integer jwksCacheIdHashCodeSample = mutualTLSJWKSCacheKey.hashCode();
        assertEquals(jwksCacheIdHashCodeSample, cacheKeyStringHashCode, "Get cache key Hashcode failed.");
    }
}
