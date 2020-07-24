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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.clientauth.privilegeduser;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.AbstractOAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.internal.PrivilegedUserAuthenticatorServiceHolder;
import org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.utils.CommonConstants;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Authenticator that can authenticate user and allow access for a user to access a OAuth endpoint on behalf of an
 * application.
 */
public class PrivilegedUserAuthenticator extends AbstractOAuthClientAuthenticator {

    private static final Log LOG = LogFactory.getLog(PrivilegedUserAuthenticator.class);
    private String userPermission;

    public PrivilegedUserAuthenticator() {

        userPermission = CommonConstants.DEFAULT_ADMIN_PERMISSION;
    }

    /**
     * Authenticate the user and returns true if the user has permission to authenticate this api.
     *
     * @param httpServletRequest      HttpServletRequest.
     * @param map                     Map of request body.
     * @param oAuthClientAuthnContext OAuth2 Client Authentication Context
     * @return True if the user can be authenticated and has required permission.
     * @throws OAuthClientAuthnException
     */
    public boolean authenticateClient(HttpServletRequest httpServletRequest, Map<String, List> map,
                                      OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {

        String[] credentials = getCredentials(map);
        if (credentials != null) {
            String userName = credentials[0];
            String password = credentials[1];
            return isUserAuthorized(userName, password);
        }
        return false;
    }

    /**
     * Returns true if this authenticator can authenticate this request, else returns false.
     *
     * @param httpServletRequest      HttpServletRequest.
     * @param map                     Map of request body.
     * @param oAuthClientAuthnContext OAuth Client Authentication context.
     * @return True if this authenticator can authenticate this request.
     */
    public boolean canAuthenticate(HttpServletRequest httpServletRequest, Map<String, List> map,
                                   OAuthClientAuthnContext oAuthClientAuthnContext) {

        if (isUserCredentialsExists(map) && httpServletRequest.getRequestURI().equals(CommonConstants.REVOKE_ENDPOINT)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User credentials body param exists. Hence this authenticator can authenticate this request");
            }
            return true;
        }
        return false;
    }

    /**
     * Retrieves the client ID which is extracted from incoming request.
     *
     * @param request                 HttpServletRequest.
     * @param bodyParams              Body parameter map of the incoming request.
     * @param oAuthClientAuthnContext OAuthClientAuthentication context.
     * @return Client ID of the OAuth2 client.
     * @throws OAuthClientAuthnException OAuth client authentication Exception.
     */
    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        Map<String, String> stringContent = getBodyParameters(bodyParams);
        oAuthClientAuthnContext.setClientId(stringContent.get(OAuth.OAUTH_CLIENT_ID));
        return oAuthClientAuthnContext.getClientId();
    }

    @Override
    public String getName() {

        return "PrivilegedUserAuthenticator";
    }

    /**
     * If this authenticator is configured in the configuration level, then it will be enabled. If not, if will be
     * disabled.
     *
     * @return True if this is enabled, else returns false.
     */
    public boolean isEnabled() {

        IdentityEventListenerConfig identityEventListenerConfig =
                IdentityUtil.readEventListenerProperty(AbstractIdentityHandler.class.getName(),
                        this.getClass().getName());
        return identityEventListenerConfig != null && Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    /**
     * Checks whether the username nad password exists in body param and returns true if present.
     *
     * @param map RequestBody
     * @return True if the username and password present, else returns false.
     */
    private boolean isUserCredentialsExists(Map<String, List> map) {

        if (getCredentials(map) == null) {
            return false;
        }
        return CommonConstants.CREDENTIAL_LENGTH == getCredentials(map).length;
    }

    /**
     * Returns username and password from the request.
     *
     * @param map HttpRequestBody
     * @return Array of username and password if they exist. Else returns null.
     */
    private String[] getCredentials(Map<String, List> map) {

        Map<String, String> stringContent = getBodyParameters(map);
        String username = stringContent.get(CommonConstants.USERNAME_PARAM);
        String password = stringContent.get(CommonConstants.PASSWORD_PARAM);
        if (username != null && password != null) {
            return new String[]{username, password};
        }
        return null;
    }

    /**
     * Returns true if the user can be authenticated and has enough permission to access the api on behalf of the
     * client.
     *
     * @param userName UserName.
     * @param password Password.
     * @return True if the user can be authenticated and has enough permission to access the api on behalf of
     * the client, else returns false.
     * @throws OAuthClientAuthnException
     */
    private boolean isUserAuthorized(String userName, String password) throws OAuthClientAuthnException {

        int tenantId = IdentityTenantUtil.getTenantIdOfUser(userName);
        String tenantDomain = MultitenantUtils.getTenantDomain(userName);
        User user = new User();
        user.setUserName(MultitenantUtils.getTenantAwareUsername(userName));
        user.setTenantDomain(tenantDomain);

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);

            UserRealm userRealm = PrivilegedUserAuthenticatorServiceHolder.getInstance().getRealmService().
                    getTenantUserRealm(tenantId);
            if (userRealm != null) {
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();
                boolean isUserAuthenticated = userStoreManager.authenticate(MultitenantUtils.
                        getTenantAwareUsername(userName), password);
                if (isUserAuthenticated) {
                    String domain = UserCoreUtil.getDomainName(userRealm.getRealmConfiguration());
                    if (StringUtils.isNotBlank(domain)) {
                        user.setUserStoreDomain(domain);
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Basic Authentication successful for the user: " + userName);
                    }
                    return handleAuthorization(user, tenantId);
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("User authentication was not successful for the user: " + userName);
                }
            } else {
                String errorMessage = "Error occurred while trying to load the user realm for the tenant: " +
                        tenantId;
                LOG.error(errorMessage);
                throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.ACCESS_DENIED);
            }

        } catch (UserStoreException | OAuthClientAuthnException e) {
            String errorMessage = "Error occurred while trying to authenticate user: " + userName;
            LOG.error(errorMessage);
            throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.ACCESS_DENIED);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        return false;
    }

    /**
     * Authorize the user from userstore and check whether the user has the required permission. Returns true if user
     * has required permission to access the resource.
     *
     * @param user     User.
     * @param tenantId TenantId.
     * @return Returns true if user has required permission to access the resource.
     * @throws OAuthClientAuthnException
     */
    private boolean handleAuthorization(User user, int tenantId) throws OAuthClientAuthnException {

        try {
            RealmService realmService = PrivilegedUserAuthenticatorServiceHolder.getInstance().getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("User permission to access to API is configured as: " + userPermission);
            }
            AuthorizationManager authorizationManager = userRealm.getAuthorizationManager();
            boolean isUserAuthorized = authorizationManager.isUserAuthorized(UserCoreUtil.addDomainToName(
                    user.getUserName(), user.getUserStoreDomain()), userPermission,
                    CarbonConstants.UI_PERMISSION_ACTION);
            if (LOG.isDebugEnabled()) {
                String msg = String.format("User is %s to access this resource.", isUserAuthorized ? "authorized" :
                        "unauthorized");
                LOG.debug(msg);
            }
            return isUserAuthorized;
        } catch (UserStoreException e) {
            String errorMessage = "Error occurred while trying to authorize user: " + user.getUserName();
            LOG.error(errorMessage);
            throw new OAuthClientAuthnException(errorMessage, OAuth2ErrorCodes.ACCESS_DENIED);
        }
    }
}
