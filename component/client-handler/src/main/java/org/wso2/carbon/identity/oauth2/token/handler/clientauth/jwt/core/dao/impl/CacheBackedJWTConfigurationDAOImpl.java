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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.JWTAuthenticationConfigurationDAO;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache.JWTConfigCache;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache.JWTConfigCacheEntry;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.dao.cache.JWTConfigCacheKey;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.exception.JWTClientAuthenticatorServiceServerException;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.core.model.JWTClientAuthenticatorConfig;

/**
 * Cached DAO layer for JWT Authenticator Configurations.
 * All the DAO access should happen through this layer to ensure single point of caching.
 */
public class CacheBackedJWTConfigurationDAOImpl implements JWTAuthenticationConfigurationDAO {

    private static final Log log = LogFactory.getLog(CacheBackedJWTConfigurationDAOImpl.class);

    private final JWTAuthenticationConfigurationDAO privateKeyJWTAuthenticationConfigurationDAO;

    public CacheBackedJWTConfigurationDAOImpl(JWTAuthenticationConfigurationDAO
                                                      privateKeyJWTAuthenticationConfigurationDAO) {

        this.privateKeyJWTAuthenticationConfigurationDAO = privateKeyJWTAuthenticationConfigurationDAO;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getPriority() {

        return 5;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JWTClientAuthenticatorConfig getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(
            String tenantDomain)
            throws JWTClientAuthenticatorServiceServerException {

        JWTClientAuthenticatorConfig cachedResult = getJWTConfigurationFromCache(tenantDomain);
        if (cachedResult != null) {
            if (log.isDebugEnabled()) {
                log.debug("JWT Authenticator configuration is not available " +
                        "in the cache for tenant domain: " + tenantDomain + ". Trying to get data from the database.");
            }
            return cachedResult;
        }

        JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig = privateKeyJWTAuthenticationConfigurationDAO.
                getPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(tenantDomain);

        addJWTAuthenticatorConfigurationToCache(JWTClientAuthenticatorConfig, tenantDomain);
        return JWTClientAuthenticatorConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain(
            JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig, String tenantDomain)
            throws JWTClientAuthenticatorServiceServerException {

        clearCaches(tenantDomain);
        privateKeyJWTAuthenticationConfigurationDAO.setPrivateKeyJWTClientAuthenticationConfigurationByTenantDomain
                (JWTClientAuthenticatorConfig, tenantDomain);
    }

    /**
     * Add JWT Authenticator configurations to the cache.
     *
     * @param JWTClientAuthenticatorConfig The JWT Authenticator configuration that should be added to the cache.
     * @param tenantDomain                 The tenant domain specific to the cache entry.
     */
    private void addJWTAuthenticatorConfigurationToCache(
            JWTClientAuthenticatorConfig JWTClientAuthenticatorConfig,
            String tenantDomain) {

        JWTConfigCacheKey cacheKey = new JWTConfigCacheKey(tenantDomain);
        JWTConfigCacheEntry cacheEntry = new JWTConfigCacheEntry(JWTClientAuthenticatorConfig);

        if (log.isDebugEnabled()) {
            log.debug("Adding JWT Authenticator configuration to Cache with Key: " + tenantDomain);
        }

        JWTConfigCache.getInstance().addToCache(cacheKey, cacheEntry, tenantDomain);
    }

    /**
     * Get JWT Authenticator configuration from the cache.
     *
     * @param tenantDomain The tenant domain specific to the cache entry.
     * @return Returns an instance of {@code JWTClientAuthenticatorConfig}(s)
     * if the cached JWT Authenticator configuration is found for the tenant. Else return {@code null}.
     */
    private JWTClientAuthenticatorConfig getJWTConfigurationFromCache(String tenantDomain) {

        JWTConfigCacheKey cacheKey = new JWTConfigCacheKey(tenantDomain);
        JWTConfigCache cache = JWTConfigCache.getInstance();
        JWTConfigCacheEntry cacheEntry = cache.getValueFromCache(cacheKey, tenantDomain);

        if (cacheEntry != null && cacheEntry.getPrivateKeyJWTClientAuthenticatorConfig() != null) {
            return cacheEntry.getPrivateKeyJWTClientAuthenticatorConfig();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry not found for cache key :" + tenantDomain);
            }
            return null;
        }
    }

    /**
     * Clear JWT Authenticator configuration caches of a particular tenant.
     *
     * @param tenantDomain The domain of the tenant.
     */
    private void clearCaches(String tenantDomain) {

        JWTConfigCacheKey cacheKey = new JWTConfigCacheKey(tenantDomain);
        JWTConfigCache.getInstance().clearCacheEntry(cacheKey, tenantDomain);
    }
}
