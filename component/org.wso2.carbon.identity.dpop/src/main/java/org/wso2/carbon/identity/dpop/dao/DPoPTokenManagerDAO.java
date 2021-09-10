/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.dpop.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

/**
 * This interface defines methods to access the database for DPoP token purposes.
 */
public interface DPoPTokenManagerDAO {

    /**
     * Returns the binding type by using the refresh token.
     *
     * @param refreshToken Refresh token.
     * @return TokenBinding from the refresh token.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the binding type.
     */
    TokenBinding getBindingFromRefreshToken(String refreshToken) throws IdentityOAuth2Exception;
}
