/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.dpop.util;

import javax.sql.DataSource;
import java.util.Date;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;


import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.dpop.util.DPoPTestConstants.*;

@PrepareForTest ({IdentityDatabaseUtil.class, Utils.class, JWK.class})
@PowerMockIgnore({"org.mockito.*", "jdk.internal.reflect.*"})
public class UtilsTest extends PowerMockTestCase {

    @Mock
    DataSource mockDataSource;

    @Mock
    JdbcTemplate mockJdbcTemplate;

    @Mock
    JWK mockJWK;

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetNewTemplate() throws Exception {

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDataSource()).thenReturn(mockDataSource);
        whenNew(JdbcTemplate.class).withAnyArguments().thenReturn(mockJdbcTemplate);
        assertEquals(Utils.getNewTemplate(), mockJdbcTemplate);
    }

    @DataProvider(name = "dpopProofProvider")
    public Object[][] dpopProofProvider() throws Exception {

        return new Object[][]{
                {DPoPProofUtil.genarateDPoPProof("RSA", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, new Date()),
                        DPoPProofUtil.RSA_DPOP_JWK_THUMBPRINT},
                {DPoPProofUtil.genarateDPoPProof("EC", DUMMY_JTI, DUMMY_HTTP_METHOD, DUMMY_HTTP_URL, new Date()),
                        DPoPProofUtil.EC_DPOP_JWK_THUMBPRINT},
                {DUMMY_DPOP_PROOF, StringUtils.EMPTY},
        };
    }

    @Test(dataProvider = "dpopProofProvider")
    public void testGetThumbprintOfKeyFromDpopProof(String dpopProof, String expectedResult) {

        try {
            String thumbprint = Utils.getThumbprintOfKeyFromDpopProof(dpopProof);
            assertEquals(thumbprint, expectedResult);
        } catch (IdentityOAuth2Exception e) {
            assertEquals(e.getErrorCode(), DPoPConstants.INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), DPoPConstants.INVALID_DPOP_ERROR);
        }
    }

    @Test
    public void testGetThumbprintOfKeyFromDpopProofWithInvalidJWK() throws Exception {

        String dPoPProof = DPoPProofUtil.genarateDPoPProof();
        String jwk = SignedJWT.parse(dPoPProof).getHeader().getJWK().toString();

        spy(JWK.class);
        when(JWK.parse(jwk)).thenReturn(mockJWK);
        when(mockJWK.getKeyType()).thenReturn(new KeyType("some_type", Requirement.REQUIRED));
        assertEquals(Utils.getThumbprintOfKeyFromDpopProof(dPoPProof), StringUtils.EMPTY);
    }
}
