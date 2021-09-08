package org.wso2.carbon.identity.dpop.internal;

import org.wso2.carbon.identity.dpop.dao.TokenBindingTypeManagerDao;

/**
 * DPoP data holder.
 */
public class DPoPDataHolder {

    private static final DPoPDataHolder dPoPDataHolder = new DPoPDataHolder();
    private TokenBindingTypeManagerDao tokenBindingTypeManagerDao;

    public static DPoPDataHolder getInstance() {

        return dPoPDataHolder;
    }

    public static DPoPDataHolder getDPoPDataHolder() {

        return dPoPDataHolder;
    }
    public TokenBindingTypeManagerDao getTokenBindingTypeManagerDao() {

        return tokenBindingTypeManagerDao;
    }

    public void setTokenBindingTypeManagerDao(
            TokenBindingTypeManagerDao tokenBindingTypeManagerDao) {

        this.tokenBindingTypeManagerDao = tokenBindingTypeManagerDao;
    }
}
