package org.wso2.carbon.identity.dpop.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

/**
 * TokenBinderType manager dao interface.
 */
public interface TokenBindingTypeManagerDao {

    /**
     * Returns the binding type by using the refresh token
     *
     * @param refreshToken
     * @return
     * @throws IdentityOAuth2Exception
     */
    TokenBinding getBindingFromRefreshToken(String refreshToken) throws IdentityOAuth2Exception;
}
