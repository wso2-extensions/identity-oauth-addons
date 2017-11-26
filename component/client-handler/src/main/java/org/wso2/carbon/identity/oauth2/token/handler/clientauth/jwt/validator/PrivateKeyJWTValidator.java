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
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.Constants;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;

public class PrivateKeyJWTValidator extends AbstractValidator<HttpServletRequest> {

    @Override
    public void validateClientAuthenticationCredentials(HttpServletRequest request) throws OAuthProblemException {
        super.validateClientAuthenticationCredentials(request);
        if (this.enforceClientAuthentication) {
            Set<String> missingParameters = new HashSet();

            if (OAuthUtils.isEmpty(request.getParameter(Constants.CLIENT_ID))) {
                missingParameters.add(Constants.CLIENT_ID);
            }
            if (OAuthUtils.isEmpty(request.getParameter(Constants.OAUTH_JWT_ASSERTION_TYPE))) {
                missingParameters.add(Constants.OAUTH_JWT_ASSERTION_TYPE);
            }
            if (OAuthUtils.isEmpty(request.getParameter(Constants.OAUTH_JWT_ASSERTION))) {
                missingParameters.add(Constants.OAUTH_JWT_ASSERTION);
            }
            if (!missingParameters.isEmpty()) {
                throw OAuthUtils.handleMissingParameters(missingParameters);
            }
        }
    }
}
