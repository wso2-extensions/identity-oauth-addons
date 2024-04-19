package org.wso2.carbon.identity.dpop.util;

import java.util.Date;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.dpop.TestUtils;
import org.wso2.carbon.identity.dpop.constant.DPoPConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;


import static org.mockito.Matchers.anyString;
import static org.testng.Assert.assertEquals;

@PrepareForTest ({IdentityDatabaseUtil.class,TestUtils.class})
@PowerMockIgnore({"org.mockito.*", "jdk.internal.reflect.*"})
public class UtilsTest extends PowerMockTestCase {

    private final String dummyHttpMethod = "mockHttpMethod";

    private final String dummyHttpUrl = "mockHttpUrl";

    @DataProvider(name = "dpopProofProvider")
    public Object[][] dpopProofProvider() throws Exception {

        return new Object[][]{
                {TestUtils.genarateDPoPProof("RSA","some_jti", dummyHttpMethod, dummyHttpUrl, new Date(), true),
                        TestUtils.RSA_DPOP_JWK_THUMBPRINT},
                {TestUtils.genarateDPoPProof("EC","some_jti", dummyHttpMethod, dummyHttpUrl, new Date(), true),
                        TestUtils.EC_DPOP_JWK_THUMBPRINT},
                {anyString(), anyString()},
        };
    }

    @Test(dataProvider = "dpopProofProvider")
    public void testGetThumbprintOfKeyFromDpopProof(String dpopProof,String expectedResult) {

        try {
            String thumbprint = Utils.getThumbprintOfKeyFromDpopProof(dpopProof);
            assertEquals(thumbprint, expectedResult);
        }catch (IdentityOAuth2Exception e){
            assertEquals(e.getErrorCode(), DPoPConstants.INVALID_DPOP_PROOF);
            assertEquals(e.getMessage(), DPoPConstants.INVALID_DPOP_ERROR);
        }
    }
}