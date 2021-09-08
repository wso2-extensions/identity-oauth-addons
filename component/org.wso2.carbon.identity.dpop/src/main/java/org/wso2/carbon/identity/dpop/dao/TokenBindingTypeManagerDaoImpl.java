package org.wso2.carbon.identity.dpop.dao;

import java.util.List;

import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.dpop.util.Utils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

/**
 * This class implements {@link TokenBindingTypeManagerDao} interface.
 */
public class TokenBindingTypeManagerDaoImpl implements TokenBindingTypeManagerDao {

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
                    preparedStatement -> {
                        preparedStatement.setString(1, refreshToken);
                    });
            return tokenBindingList.get(0);
        } catch (DataAccessException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
    }
}
