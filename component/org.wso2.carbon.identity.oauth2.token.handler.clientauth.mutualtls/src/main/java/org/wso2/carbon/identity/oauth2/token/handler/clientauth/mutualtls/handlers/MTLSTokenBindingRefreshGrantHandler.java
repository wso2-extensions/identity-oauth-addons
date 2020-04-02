/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.handlers;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * If MTLS token binding is used (MTLSTokenBindingAuthorizationCodeGrantHandler), the certificate of the client is
 * bounded to the access token using a hidden scope. This class is used to remove the hidden scope from the token
 * response.
 *
 * @see <href="https://tools.ietf.org/html/draft-ietf-oauth-mtls-17">IETF OAuth MTLS</>
 */
public class MTLSTokenBindingRefreshGrantHandler extends RefreshGrantHandler {

    private static final Log log = LogFactory.getLog(MTLSTokenBindingRefreshGrantHandler.class);

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO = super.issue(tokReqMsgCtx);
        tokReqMsgCtx.setScope(getReducedResponseScopes(tokReqMsgCtx.getScope()));
        return oAuth2AccessTokenRespDTO;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        String[] grantedScopes = tokReqMsgCtx.getScope();
        if (!super.validateScope(tokReqMsgCtx)) {
            return false;
        }

        String[] requestedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        String[] modifiedScopes;
        if (ArrayUtils.isNotEmpty(requestedScopes)) {
            if (ArrayUtils.isEmpty(grantedScopes)) {
                return false;
            }

            // Add cert hash scope from previously granted scopes.
            ArrayList<String> requestedScopeList = new ArrayList<>(Arrays.asList(requestedScopes));
            for (String scope : grantedScopes) {
                if (isAllowedScope(scope)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Adding custom scope " + scope + " to the requested scopes");
                    }
                    requestedScopeList.add(scope);
                }
            }
            modifiedScopes = requestedScopeList.toArray(new String[0]);
            tokReqMsgCtx.setScope(modifiedScopes);
        }
        return true;
    }

    /**
     * Remove the certificate thumbprint prefixed scope from the space delimited list of authorized scopes.
     *
     * @param scopes Authorized scopes of the token.
     * @return scopes by removing the custom scope.
     */
    private String[] getReducedResponseScopes(String[] scopes) {

        if (scopes != null && scopes.length > 0) {
            List<String> scopesList = new LinkedList<>(Arrays.asList(scopes));
            scopesList.removeIf(s -> s.startsWith(MutualTLSUtil.CERT_THUMBPRINT));
            return scopesList.toArray(new String[0]);
        }
        return scopes;
    }

    private boolean isAllowedScope(String scope) {

        return scope.startsWith(MutualTLSUtil.CERT_THUMBPRINT) ||
                scope.startsWith(MutualTLSUtil.TIMESTAMP_SCOPE_PREFIX);
    }
}
