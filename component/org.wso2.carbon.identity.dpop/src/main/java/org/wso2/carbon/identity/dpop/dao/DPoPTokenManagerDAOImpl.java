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

import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.util.List;

/**
 * This class implements {@link DPoPTokenManagerDAO} interface.
 */
public class DPoPTokenManagerDAOImpl implements DPoPTokenManagerDAO {

    @Override
    public TokenBinding getBindingFromRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        JdbcTemplate jdbcTemplate = Utils.getNewTemplate();
        try {
            List<TokenBinding> tokenBindingList = jdbcTemplate.executeQuery(
                    DPoPConstants.SQLQueries.RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN,
                    (resultSet, rowNumber) -> {
                        TokenBinding tokenBinding = new TokenBinding();
                        tokenBinding.setBindingType(resultSet.getString(1));
                        tokenBinding.setBindingValue(resultSet.getString(2));

                        return tokenBinding;
                    },
                    preparedStatement ->
                            preparedStatement.setString(1, refreshToken));

            return tokenBindingList.isEmpty() ? null : tokenBindingList.get(0);
        } catch (DataAccessException e) {
            String error = String.format("Error obtaining token binding type using refresh token: %s.",
                    refreshToken);
            throw new IdentityOAuth2Exception(error, e);
        }
    }
}