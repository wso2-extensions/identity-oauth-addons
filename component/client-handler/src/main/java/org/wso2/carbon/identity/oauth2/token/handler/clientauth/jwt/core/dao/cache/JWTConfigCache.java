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

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Implements a cache to store JWT Configurations.
 */
public class JWTConfigCache extends AuthenticationBaseCache<JWTConfigCacheKey, JWTConfigCacheEntry> {
    public static final String PRIVATE_KEY_JWT_CONFIG_CACHE = "PrivateKeyJWTConfig";
    private static volatile JWTConfigCache instance;

    private JWTConfigCache() {
        super(PRIVATE_KEY_JWT_CONFIG_CACHE);
    }

    public static JWTConfigCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (JWTConfigCache.class) {
                if (instance == null) {
                    instance = new JWTConfigCache();
                }
            }
        }
        return instance;
    }
}
