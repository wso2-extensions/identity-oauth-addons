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
import org.apache.commons.lang.StringUtils;
import org.testng.Assert;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.JWTValidator;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;

public class JWTTestUtil {

    /**
     * Return a JWT string with provided info, and default time
     * @param issuer
     * @param subject
     * @param jti
     * @param audience
     * @param algorythm
     * @param privateKey
     * @param notBeforeMillis
     * @return
     * @throws IdentityOAuth2Exception
     */
    public static String buildJWT(String issuer, String subject, String jti, String audience, String algorythm,
                                  Key privateKey, long notBeforeMillis)
            throws IdentityOAuth2Exception {

        long lifetimeInMillis = 3600 * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(subject);
        jwtClaimsSet.setAudience(Arrays.asList(audience));
        jwtClaimsSet.setJWTID(jti);
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));

        if (notBeforeMillis > 0) {
            jwtClaimsSet.setNotBeforeTime(new Date(curTimeInMillis + notBeforeMillis));
        }
        if (JWSAlgorithm.NONE.getName().equals(algorythm)) {
            return new PlainJWT(jwtClaimsSet).serialize();
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
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(subject);
        jwtClaimsSet.setAudience(Arrays.asList(audience));
        jwtClaimsSet.setJWTID(jti);
        jwtClaimsSet.setExpirationTime(new Date(issuedTime + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(issuedTime));

        if (notBeforeMillis > 0) {
            jwtClaimsSet.setNotBeforeTime(new Date(issuedTime + notBeforeMillis));
        }
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
     * Create a auth-app in the given tenant with given consumerKey and consumerSecreat
     * @param consumerKey
     * @param consumerSecret
     * @param tenantId
     */
    public static void createApplication(String consumerKey, String consumerSecret, int tenantId) {
        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)){
            prepStmt.setString(1, consumerKey);
            prepStmt.setString(2, consumerSecret);
            prepStmt.setString(3, "testUser");
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
            prepStmt.setString(6, "oauth2-app");
            prepStmt.setString(7, "OAuth-2.0");
            prepStmt.setString(8, "some-call-back");
            prepStmt.setString(9, "refresh_token urn:ietf:params:oauth:grant-type:saml2-bearer implicit password " +
                    "client_credentials iwa:ntlm authorization_code urn:ietf:params:oauth:grant-type:jwt-bearer");
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            Assert.fail("Unable to add Oauth application.");
            //throw new TestNGException("Unable to add Oauth application.");
        }
    }

    /**
     * Read Keystore from the file identified by given keystorename, password
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
     * @param properties
     * @return
     */
    public static JWTValidator getJWTValidator(Properties properties) {
        int rejectBeforePeriod;
        boolean cacheUsedJTI = true;
        String validAudience = null;
        String validIssuer = null;
        boolean preventTokenReuse = true;
        try {

            String rejectBeforePeriodConfigVal = properties.getProperty(Constants.REJECT_BEFORE_PERIOD);
            if (StringUtils.isNotEmpty(rejectBeforePeriodConfigVal)) {
                rejectBeforePeriod = Integer.parseInt(rejectBeforePeriodConfigVal);
            } else {
                rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
            }

            String cacheUsedJTIConfigVal = properties.getProperty(Constants.USE_CACHE_FOR_JTI);
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

        } catch (NumberFormatException e) {
            rejectBeforePeriod = Constants.DEFAULT_VALIDITY_PERIOD_IN_MINUTES;
        }

        return new JWTValidator(rejectBeforePeriod, preventTokenReuse, cacheUsedJTI,
                validAudience, validIssuer);
    }
}
