package org.wso2.carbon.identity.dpop.util;

import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.core.persistence.UmPersistenceManager;

/**
 * This class provides utility functions for dpop implementation.
 */
public class Utils {

    public static JdbcTemplate getNewTemplate() {

        return new JdbcTemplate(UmPersistenceManager.getInstance().getDataSource());
    }
}
