package org.wso2.carbon.identity.dpop.util;

public enum OuthTokenType {

    BEARER("Bearer"),
    DPOP("DPoP");

    private String tokenTypeName;

    OuthTokenType(String tokenTypeName) {
        this.tokenTypeName = tokenTypeName;
    }

    @Override
    public String toString() {
        return tokenTypeName;
    }
}
