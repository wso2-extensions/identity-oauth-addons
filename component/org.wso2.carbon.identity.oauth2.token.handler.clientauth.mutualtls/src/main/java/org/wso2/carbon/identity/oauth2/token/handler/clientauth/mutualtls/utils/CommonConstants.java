package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils;

public class CommonConstants {

    public static final String JWKS_URI = "jwksURI";
    public static final String CERT_THUMBPRINT = "x5t";
    public static final String TIMESTAMP_SCOPE_PREFIX = "TIME_";
    public static final String CERT_THUMBPRINT_SEPARATOR = ":";
    public static final String CONFIRMATION_CLAIM_ATTRIBUTE = "cnf";
    public static final String SHA256_DIGEST_ALGORITHM = "SHA256";
    public static final String AUTHENTICATOR_TYPE_PARAM = "authenticatorType";
    public static final String AUTHENTICATOR_TYPE_MTLS = "mtls";
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String MTLS_AUTH_HEADER = "MutualTLS.ClientCertificateHeader";
    public static final String X5T = "x5t";
    public static final String X5C = "x5c";
    public static final String X509 = "X.509";
    public static final String HTTP_CONNECTION_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPConnectionTimeout";
    public static final String HTTP_READ_TIMEOUT_XPATH = "JWTValidatorConfigs.JWKSEndpoint" +
            ".HTTPReadTimeout";
    public static final String KEYS = "keys";

}
