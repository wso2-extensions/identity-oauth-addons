package org.wso2.carbon.identity.dpop.cache;

import org.wso2.carbon.identity.core.cache.CacheEntry;

public class DPoPJKTCacheEntry extends CacheEntry {

    private String dpopJkt;

    public DPoPJKTCacheEntry(String dpopJkt) { this.dpopJkt = dpopJkt; }

    public String getDpopJkt() { return dpopJkt; }
}
