package org.wso2.carbon.identity.dpop.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

public interface DPoPJKTDAO  {

    void insertDPoPJKT(AuthzCodeDO authzCodeDO, String dpopJkt) throws IdentityOAuth2Exception;

    String getDPoPJKTFromAuthzCode(String authzCode) throws IdentityOAuth2Exception;
}
