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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.grant;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.mockito.Mockito;
import org.mockito.internal.util.reflection.Whitebox;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.grant.JWTClientCredentialGrantValidator;

import javax.servlet.http.HttpServletRequest;

public class JWTClientCredentialGrantValidatorTest {

    HttpServletRequest mockedRequest;
    private org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.validator.grant.JWTClientCredentialGrantValidator JWTClientCredentialGrantValidator;

    @BeforeClass
    public void setUp() throws Exception {
        mockedRequest = Mockito.mock(HttpServletRequest.class);
        JWTClientCredentialGrantValidator = new JWTClientCredentialGrantValidator();
        Whitebox.setInternalState(JWTClientCredentialGrantValidator, "enforceClientAuthentication", true);
    }

    @Test(expectedExceptions = OAuthProblemException.class)
    public void testValidateClientAuthenticationCredentialsInvalidParams() throws Exception {
        Mockito.when(mockedRequest.getParameter(Constants.CLIENT_ID)).thenReturn("");
        Mockito.when(mockedRequest.getParameter(Constants.OAUTH_JWT_ASSERTION_TYPE)).thenReturn("");
        Mockito.when(mockedRequest.getParameter(Constants.OAUTH_JWT_ASSERTION)).thenReturn("");
        JWTClientCredentialGrantValidator.validateClientAuthenticationCredentials(mockedRequest);
    }
}