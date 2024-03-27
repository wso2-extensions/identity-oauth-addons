package org.wso2.carbon.identity.dpop.cache;

import java.io.Serializable;

public class DPoPJKTCacheKey implements Serializable {

    private String cacheKeyString;

    public DPoPJKTCacheKey(String clientId, String authzCode) {

        this.cacheKeyString = clientId + ":" + authzCode;
    }

    private static final long serialVersionUID = 5023478840178742769L;
    public String getCacheKeyString() { return cacheKeyString; }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DPoPJKTCacheKey)) {
            return false;
        }
        return this.cacheKeyString.equals(((DPoPJKTCacheKey) o).getCacheKeyString());
    }

    @Override
    public int hashCode() {
        return cacheKeyString.hashCode();
    }
}
