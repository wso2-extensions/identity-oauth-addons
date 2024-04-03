package org.wso2.carbon.identity.dpop.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.listener.OauthDPoPInterceptorHandlerProxy;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;

public class DPoPJKTDAOImpl implements DPoPJKTDAO {

    private static final Log log = LogFactory.getLog(DPoPJKTDAOImpl.class);
    private static TokenPersistenceProcessor hashingPersistenceProcessor;

    public DPoPJKTDAOImpl() {

        hashingPersistenceProcessor = new HashingPersistenceProcessor();
    }
    @Override
    public void insertDPoPJKT(AuthzCodeDO authzCodeDO, String dpopJkt) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Persisting dp code (hashed): " + DigestUtils.sha256Hex(dpopJkt) + " for client: "
                    + authzCodeDO.getConsumerKey() + " user: " + authzCodeDO.getAuthorizedUser().getLoggableUserId());
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            String sql = SQLQueries.INSERT_DPOP_JKT;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, authzCodeDO.getAuthzCodeId());
            prepStmt.setString(2, dpopJkt);
            prepStmt.execute();
        }catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing the dpop_jkt for consumer key : "
                    + authzCodeDO.getConsumerKey(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

    }

    @Override
    public String getDPoPJKTFromAuthzCode(String authzCode) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        try {
            String sql = SQLQueries.RETRIEVE_DPOP_JKT_BY_AUTHORIZATION_CODE;
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, hashingPersistenceProcessor.getProcessedAuthzCode(authzCode));
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                String dpopJkt = resultSet.getString("DPOP_JKT");
                //ensures the function returns null only when there is no entry in DB for the given authzCode
                return (dpopJkt == null) ? "" : dpopJkt;
            }
            return null;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when retrieving dpop_jkt for consumer key : " + authzCode, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }
}
