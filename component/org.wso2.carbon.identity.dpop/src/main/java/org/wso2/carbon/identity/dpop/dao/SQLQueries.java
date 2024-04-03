package org.wso2.carbon.identity.dpop.dao;

public class SQLQueries {

    public static final String RETRIEVE_TOKEN_BINDING_BY_REFRESH_TOKEN =
            "SELECT BINDING.TOKEN_BINDING_TYPE,BINDING.TOKEN_BINDING_VALUE,BINDING.TOKEN_BINDING_REF " +
                    "FROM IDN_OAUTH2_ACCESS_TOKEN TOKEN LEFT JOIN IDN_OAUTH2_TOKEN_BINDING BINDING ON " +
                    "TOKEN.TOKEN_ID=BINDING.TOKEN_ID WHERE TOKEN.REFRESH_TOKEN = ? " +
                    "AND BINDING.TOKEN_BINDING_TYPE = ?";

    public static final String INSERT_DPOP_JKT = "INSERT INTO IDN_OAUTH_DPOP_JKT (CODE_ID, DPOP_JKT) VALUES (?, ?)";

    public static final String RETRIEVE_DPOP_JKT_BY_AUTHORIZATION_CODE = "SELECT DPOP_JKT FROM IDN_OAUTH_DPOP_JKT " +
            "WHERE CODE_ID = (SELECT CODE_ID FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE AUTHORIZATION_CODE_HASH = ?)";
}
