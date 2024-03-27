package org.wso2.carbon.identity.dpop.cache;

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.utils.CarbonUtils;

public class DPoPJKTCache extends AuthenticationBaseCache<DPoPJKTCacheKey, DPoPJKTCacheEntry> {

    private static final String DPOP_JKT_CACHE_NAME = "DPoPJKTCache";

    private static volatile DPoPJKTCache instance = new DPoPJKTCache();

    private DPoPJKTCache() {
        super(DPOP_JKT_CACHE_NAME);
    }

    public static DPoPJKTCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (DPoPJKTCache.class) {
                if (instance == null) {
                    instance = new DPoPJKTCache();
                }
            }
        }
        return instance;
    }
}
