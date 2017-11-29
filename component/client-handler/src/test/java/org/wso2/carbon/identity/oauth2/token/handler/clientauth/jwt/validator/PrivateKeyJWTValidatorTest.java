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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator;


import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.Whitebox;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

public class PrivateKeyJWTValidatorTest {
    private PrivateKeyJWTValidator privateKeyJWTValidator;
    HttpServletRequest mockedRequest;

    @BeforeClass
    public void setUp() throws Exception {
        privateKeyJWTValidator = new PrivateKeyJWTValidator(true);
        Whitebox.setInternalState(this.privateKeyJWTValidator, "enforceClientAuthentication", true);
        mockedRequest = Mockito.mock(HttpServletRequest.class);

    }

    @Test()
    public void testValidateClientAuthenticationCredentials() throws Exception {
        Map<String, String[]> paramMap = new HashMap<String, String[]>();
        paramMap.put(Constants.CLIENT_ID, new String[]{"some-id"});
        paramMap.put(Constants.OAUTH_JWT_ASSERTION_TYPE, new String[]{"some-assertion-type"});
        paramMap.put(Constants.OAUTH_JWT_ASSERTION, new String[]{"some-assertion"});
        Mockito.when(mockedRequest.getParameterMap()).thenReturn((Map<String, String[]>) paramMap);
        Mockito.when(mockedRequest.getParameter(Constants.CLIENT_ID)).thenReturn("some-id");
        Mockito.when(mockedRequest.getParameter(Constants.OAUTH_JWT_ASSERTION_TYPE)).thenReturn("some-assertion-type");
        Mockito.when(mockedRequest.getParameter(Constants.OAUTH_JWT_ASSERTION)).thenReturn("some-assertion");
        privateKeyJWTValidator.validateClientAuthenticationCredentials(mockedRequest);
    }

    @Test(expectedExceptions = OAuthProblemException.class)
    public void testValidateClientAuthenticationCredentialsWithMissingParam() throws Exception {
        Map<String, String[]> paramMap = new HashMap<String, String[]>();
        paramMap.put(Constants.CLIENT_ID, new String[]{"some-id"});
        paramMap.put(Constants.OAUTH_JWT_ASSERTION_TYPE, new String[]{"some-assertion-type"});
        paramMap.put(Constants.OAUTH_JWT_ASSERTION, new String[]{"some-assertion"});
        Mockito.when(mockedRequest.getParameterMap()).thenReturn((Map<String, String[]>) paramMap);
        Mockito.when(mockedRequest.getParameter(Constants.CLIENT_ID)).thenReturn("");
        Mockito.when(mockedRequest.getParameter(Constants.OAUTH_JWT_ASSERTION_TYPE)).thenReturn("");
        Mockito.when(mockedRequest.getParameter(Constants.OAUTH_JWT_ASSERTION)).thenReturn("");
        privateKeyJWTValidator.validateClientAuthenticationCredentials(mockedRequest);
    }
}