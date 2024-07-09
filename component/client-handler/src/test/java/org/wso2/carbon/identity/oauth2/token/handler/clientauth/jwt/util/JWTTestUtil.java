/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * under the License
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidator;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.DEFAULT_VALUE_FOR_PREVENT_TOKEN_REUSE;

public class JWTTestUtil {

    public static final String H2_SCRIPT_NAME = "identity.sql";
    private static final String DB_NAME = "Identity";
    public static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();

    public static void initiateH2Base() throws Exception {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + DB_NAME);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + getFilePath(H2_SCRIPT_NAME) + "'");
        }
        dataSourceMap.put(DB_NAME, dataSource);
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbscripts",
                    fileName).toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    public static Connection getConnection() throws SQLException {

        if (dataSourceMap.get(DB_NAME) != null) {
            return dataSourceMap.get(DB_NAME).getConnection();
        }
        throw new RuntimeException("No data source initiated for database: " + DB_NAME);
    }

    public static Connection spyConnection(Connection connection) throws SQLException {

        Connection spy = spy(connection);
        doNothing().when(spy).close();
        return spy;
    }

    public static void closeH2Base() throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(DB_NAME);
        if (dataSource != null) {
            dataSource.close();
        }
    }
    public static String buildJWT(String issuer, String subject, String jti, String audience, String algorithm,
                                  Key privateKey, long notBeforeMillis)
            throws IdentityOAuth2Exception {

        long lifetimeInMillis = 3600 * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        jwtClaimsSetBuilder.audience(Arrays.asList(audience));
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSetBuilder.issueTime(new Date(curTimeInMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(curTimeInMillis + notBeforeMillis));
        }
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(algorithm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        } else if (JWSAlgorithm.RS512.getName().equals(algorithm)) {
            return signJWTWithRSA512(jwtClaimsSet, privateKey);
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    public static String buildJWT(String issuer, String subject, String jti, String audience, String algorythm,
                                  Key privateKey, long notBeforeMillis, long lifetimeInMillis, long issuedTime)
            throws IdentityOAuth2Exception {

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        if (issuedTime < 0) {
            issuedTime = curTimeInMillis;
        }
        if (lifetimeInMillis <= 0) {
            lifetimeInMillis = 3600 * 1000;
        }
        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        jwtClaimsSetBuilder.audience(Arrays.asList(audience));
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date(issuedTime + lifetimeInMillis));
        jwtClaimsSetBuilder.issueTime(new Date(issuedTime));
        jwtClaimsSetBuilder.notBeforeTime(new Date(notBeforeMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(issuedTime + notBeforeMillis));
        }
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(algorythm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    public static String buildExpiredJWT(String issuer, String subject, String jti, String audience, String algorythm,
                                         Key privateKey, long notBeforeMillis, long lifetimeInMillis, long issuedTime)
            throws IdentityOAuth2Exception {

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        if (issuedTime < 0) {
            issuedTime = curTimeInMillis;
        }
        if (lifetimeInMillis <= 0) {
            lifetimeInMillis = 3600 * 1000;
        }
        // Set claims to jwt token.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issuer(issuer);
        jwtClaimsSetBuilder.subject(subject);
        jwtClaimsSetBuilder.audience(Arrays.asList(audience));
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.expirationTime(new Date(issuedTime - lifetimeInMillis));
        jwtClaimsSetBuilder.issueTime(new Date(issuedTime));
        jwtClaimsSetBuilder.notBeforeTime(new Date(notBeforeMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSetBuilder.notBeforeTime(new Date(issuedTime + notBeforeMillis));
        }
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (JWSAlgorithm.NONE.getName().equals(algorythm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWTWithRSA(jwtClaimsSet, privateKey);
    }

    /**
     * sign JWT token from RSA algorithm
     *
     * @param jwtClaimsSet contains JWT body
     * @param privateKey
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    public static String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, Key privateKey)
            throws IdentityOAuth2Exception {

        try {
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }

    /**
     * Sign JWT using the RS512 algorithm.
     *
     * @param jwtClaimsSet    Set of claims to be included in the JWT.
     * @param privateKey      Private key used to sign the JWT.
     * @return Signed JWT value.
     * @throws IdentityOAuth2Exception An exception is thrown if an error occurs while signing the JWT.
     */
    public static String signJWTWithRSA512(JWTClaimsSet jwtClaimsSet, Key privateKey)
            throws IdentityOAuth2Exception {

        try {
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS512), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT.", e);
        }
    }

    /**
     * Read Keystore from the file identified by given keystorename, password
     *
     * @param keystoreName
     * @param password
     * @param home
     * @return
     * @throws Exception
     */
    public static KeyStore getKeyStoreFromFile(String keystoreName, String password,
                                               String home) throws Exception {

        Path tenantKeystorePath = Paths.get(home, "repository",
                "resources", "security", keystoreName);
        FileInputStream file = new FileInputStream(tenantKeystorePath.toString());
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, password.toCharArray());
        return keystore;
    }

    /**
     * Create and return a JWTValidator instance with given properties
     *
     * @param properties
     * @return
     */
    public static JWTValidator getJWTValidator(Properties properties) {

        int rejectBeforePeriod;
        boolean cacheUsedJTI = true;
        String validAudience = null;
        String validIssuer = null;
        boolean preventTokenReuse = DEFAULT_VALUE_FOR_PREVENT_TOKEN_REUSE;
        List<String> mandatoryClaims = new ArrayList<>();
        try {

            String rejectBeforePeriodConfigVal = properties.getProperty(Constants.REJECT_BEFORE_IN_MINUTES);
            if (StringUtils.isNotEmpty(rejectBeforePeriodConfigVal)) {
                rejectBeforePeriod = Integer.parseInt(rejectBeforePeriodConfigVal);
            } else {
                rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
            }

            String cacheUsedJTIConfigVal = properties.getProperty("EnableCacheForJTI");
            if (StringUtils.isNotEmpty(cacheUsedJTIConfigVal)) {
                cacheUsedJTI = Boolean.parseBoolean(cacheUsedJTIConfigVal);
            } else {
                cacheUsedJTI = Constants.DEFAULT_ENABLE_JTI_CACHE;
            }

            String validAudienceConfigVal = properties.getProperty("ValidAudience");
            if (StringUtils.isNotEmpty(validAudienceConfigVal)) {
                validAudience = validAudienceConfigVal;
            } else {
                validAudience = null;
            }

            String validIssuerConfigVal = properties.getProperty("ValidIssuer");
            if (StringUtils.isNotEmpty(validIssuerConfigVal)) {
                validIssuer = validIssuerConfigVal;
            } else {
                validIssuer = null;
            }

            String preventTokenReuseProperty = properties.getProperty("PreventTokenReuse");
            if (StringUtils.isNotEmpty(preventTokenReuseProperty)) {
                preventTokenReuse = Boolean.parseBoolean(preventTokenReuseProperty);
            }

            String mandatory = properties.getProperty("mandatory");
            if (StringUtils.isNotEmpty(mandatory)) {
                mandatoryClaims.add(mandatory);
            }

        } catch (NumberFormatException e) {
            rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
        }

        return new JWTValidator(preventTokenReuse, validAudience, rejectBeforePeriod, validIssuer, mandatoryClaims
                , cacheUsedJTI);
    }
}
