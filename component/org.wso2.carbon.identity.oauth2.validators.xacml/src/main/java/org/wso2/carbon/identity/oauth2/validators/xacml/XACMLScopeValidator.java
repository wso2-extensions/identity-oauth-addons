/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *
 */

package org.wso2.carbon.identity.oauth2.validators.xacml;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaxen.JaxenException;
import org.wso2.balana.utils.Constants.PolicyConstants;
import org.wso2.balana.utils.exception.PolicyBuilderException;
import org.wso2.balana.utils.policy.PolicyBuilder;
import org.wso2.balana.utils.policy.dto.RequestElementDTO;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.PDPConstants;
import org.wso2.carbon.identity.entitlement.common.EntitlementPolicyConstants;
import org.wso2.carbon.identity.entitlement.common.dto.RequestDTO;
import org.wso2.carbon.identity.entitlement.common.dto.RowDTO;
import org.wso2.carbon.identity.entitlement.common.util.PolicyCreatorUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.xacml.constants.XACMLScopeValidatorConstants;
import org.wso2.carbon.identity.oauth2.validators.xacml.internal.OAuthScopeValidatorDataHolder;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.stream.XMLStreamException;

/**
 * The Scope Validation implementation. This uses XACML policies to evaluate scope validation defined by the user.
 */
public class XACMLScopeValidator extends OAuth2ScopeValidator {

    private static final String SCOPE_VALIDATOR_NAME = "XACML Scope Validator";
    private static final Log log = LogFactory.getLog(XACMLScopeValidator.class);

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {

        if (isUnauthorizedToken(accessTokenDO)) {
            return false;
        }
        String consumerKey = accessTokenDO.getConsumerKey();
        return validateScope(accessTokenDO.getScope(), accessTokenDO.getAuthzUser(), consumerKey,
                XACMLScopeValidatorConstants.ACTION_VALIDATE, resource, accessTokenDO.getAccessToken());
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws
            IdentityOAuth2Exception {

        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        return validateScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope(), tokReqMsgCtx.getAuthorizedUser(),
                consumerKey, XACMLScopeValidatorConstants.ACTION_SCOPE_VALIDATE, null, null);

    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws
            IdentityOAuth2Exception {

        String consumerKey = oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey();
        return validateScope(oauthAuthzMsgCtx.getAuthorizationReqDTO().getScopes(),
                oauthAuthzMsgCtx.getAuthorizationReqDTO().getUser(), consumerKey,
                XACMLScopeValidatorConstants.ACTION_SCOPE_VALIDATE, null, null);
    }

    /**
     * Validates the given set of scope against the XACML policy published.
     * @param scopes Set of scopes.
     * @param authenticatedUser Authenticated user.
     * @param consumerKey ClientId of service provider.
     * @param action ActionId
     * @param resource Resource
     * @return True is all scopes are valid. False otherwise.
     * @throws IdentityOAuth2Exception by an Underline method.
     */
    private boolean validateScope(String[] scopes, AuthenticatedUser authenticatedUser, String consumerKey,
                                  String action, String resource, String token) throws IdentityOAuth2Exception {

        boolean isValid = false;
        FrameworkUtils.startTenantFlow(authenticatedUser.getTenantDomain());
        if (StringUtils.isNotEmpty(consumerKey)) {
            try {
                OAuthAppDO oAuthAppDO = getOAuthAppDO(consumerKey);
                String request = createRequest(scopes, authenticatedUser, oAuthAppDO, action, resource, token);
                isValid = isRequestPermit(request, oAuthAppDO, authenticatedUser.toFullQualifiedUsername());

            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception(String.format("Error occurred when retrieving corresponding app for this specific" +
                        " client id. %s of user %s ", consumerKey, authenticatedUser.toFullQualifiedUsername()), e);

            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
        return isValid;
    }

    /**
     * Creates XACML Request string with the parameters retrieved from the request.
     *
     * @param scopes            Set of scopes.
     * @param authenticatedUser Authenticated user.
     * @param oAuthAppDO        OAuth application.
     * @return XACML Request string.
     */
    private String createRequest(String[] scopes, AuthenticatedUser authenticatedUser, OAuthAppDO oAuthAppDO,
                                 String action, String resource, String token) throws IdentityOAuth2Exception {

        List<RowDTO> rowDTOs = new ArrayList<>();
        RowDTO actionDTO = createRowDTO(action, XACMLScopeValidatorConstants.AUTH_ACTION_ID,
                XACMLScopeValidatorConstants.ACTION_CATEGORY);
        RowDTO spNameDTO = createRowDTO(oAuthAppDO.getApplicationName(), XACMLScopeValidatorConstants.SP_NAME_ID,
                XACMLScopeValidatorConstants.SP_CATEGORY);
        RowDTO usernameDTO = createRowDTO(authenticatedUser.getUserName(), XACMLScopeValidatorConstants.USERNAME_ID,
                XACMLScopeValidatorConstants.USER_CATEGORY);
        RowDTO userStoreDomainDTO = createRowDTO(authenticatedUser.getUserStoreDomain(),
                XACMLScopeValidatorConstants.USER_STORE_ID, XACMLScopeValidatorConstants.USER_CATEGORY);
        RowDTO userTenantDomainDTO = createRowDTO(authenticatedUser.getTenantDomain(),
                XACMLScopeValidatorConstants.USER_TENANT_DOMAIN_ID, XACMLScopeValidatorConstants.USER_CATEGORY);
        RowDTO resourceDTO = createRowDTO(resource, EntitlementPolicyConstants.RESOURCE_ID, PDPConstants
                .RESOURCE_CATEGORY_URI);
        RowDTO subjectDTO =
                createRowDTO(authenticatedUser.toString(), PolicyConstants.SUBJECT_ID_DEFAULT,
                        PolicyConstants.SUBJECT_CATEGORY_URI);
        rowDTOs.add(subjectDTO);

        rowDTOs.add(actionDTO);
        rowDTOs.add(spNameDTO);
        rowDTOs.add(usernameDTO);
        rowDTOs.add(userStoreDomainDTO);
        rowDTOs.add(userTenantDomainDTO);
        rowDTOs.add(resourceDTO);

        for (String scope : scopes) {
            RowDTO scopeNameDTO = createRowDTO(scope, XACMLScopeValidatorConstants.SCOPE_ID,
                    XACMLScopeValidatorConstants.SCOPE_CATEGORY);
            rowDTOs.add(scopeNameDTO);
        }

        createRowDTOForUserType(authenticatedUser, rowDTOs);
        createRowDTOsForUserAttributes(authenticatedUser, action, rowDTOs, token);

        RequestDTO requestDTO = new RequestDTO();
        requestDTO.setRowDTOs(rowDTOs);

        RequestElementDTO requestElementDTO = PolicyCreatorUtil.createRequestElementDTO(requestDTO);
        String request = null;
        try {
            request = PolicyBuilder.getInstance().buildRequest(requestElementDTO);
        } catch (PolicyBuilderException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when building  XACML request of user " +
                    "%s.", authenticatedUser.toFullQualifiedUsername()), e);
        }

        if (log.isDebugEnabled()) {
            log.debug("XACML scope validation request :\n" + request);
        }
        return request;
    }

    /**
     * Validates the XACML request using XACML engine with the parameters authApp and authzUser, and returns whether
     * to permit or not.
     * @param request XACML request.
     * @param oAuthAppDO Application.
     * @param authzUser Fully qualified name of the user.
     * @return Returns true if the XACML response is permit or NotApplicable. Else returns false.
     * @throws IdentityOAuth2Exception Exception
     */
    private boolean isRequestPermit(String request, OAuthAppDO oAuthAppDO, String authzUser)
            throws IdentityOAuth2Exception {

        boolean permit = false;
        try {
            String responseString = OAuthScopeValidatorDataHolder.getInstance().getEntitlementService()
                    .getDecision(request);
            if (log.isDebugEnabled()) {
                log.debug("XACML scope validation response :\n" + responseString);
            }
            String response = extractDecisionFromXACMLResponse(responseString);
            if (isResponseNotApplicable(response)) {
                log.warn(String.format("No applicable rule for service provider '%s@%s'. Add a validating policy "
                                + "(or unset Scope Validation using XACMLScopeValidator) to fix this warning.",
                        oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
                permit = true;
            } else if (isResponsePermit(response)) {
                permit = true;
            }
        } catch (XMLStreamException | JaxenException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when reading XACML response of " +
                    "user %s.", authzUser), e);
        } catch (EntitlementException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when evaluating XACML request of user" +
                    " %s.", authzUser), e);
        }
        return permit;
    }

    private OAuthAppDO getOAuthAppDO(String consumerKey) throws IdentityOAuth2Exception, InvalidOAuthClientException {

        return OAuth2Util.getAppInformationByClientId(consumerKey);
    }

    /**
     * Creates RowDTO object of xacml request using the resource name, attribute id, category value.
     *
     * @param resourceName  resource name
     * @param attributeId   attribute id of the resource
     * @param categoryValue category of the resource
     * @return RowDTO
     */
    private RowDTO createRowDTO(String resourceName, String attributeId, String categoryValue) {

        RowDTO rowDTO = new RowDTO();
        rowDTO.setAttributeValue(resourceName);
        rowDTO.setAttributeDataType(EntitlementPolicyConstants.STRING_DATA_TYPE);
        rowDTO.setAttributeId(attributeId);
        rowDTO.setCategory(categoryValue);
        return rowDTO;
    }

    /**
     * This extracts the decision from the xacml response.
     *
     * @param xacmlResponse xacml response to be extracted
     * @return extracted decision
     * @throws XMLStreamException exception when converting string response to XML
     * @throws JaxenException     exception
     */
    private String extractDecisionFromXACMLResponse(String xacmlResponse) throws XMLStreamException, JaxenException {

        AXIOMXPath axiomxPath = new AXIOMXPath(XACMLScopeValidatorConstants.DECISION_XPATH);
        axiomxPath.addNamespace(XACMLScopeValidatorConstants.XACML_NS_PREFIX, EntitlementPolicyConstants
                .REQ_RES_CONTEXT_XACML3);
        OMElement rootElement = new StAXOMBuilder(new ByteArrayInputStream(xacmlResponse.getBytes(StandardCharsets
                .UTF_8))).getDocumentElement();
        return axiomxPath.stringValueOf(rootElement);
    }

    /**
     * Decide whether the token has is authorized.
     *
     * @param accessTokenDO access token
     * @return boolean
     */
    private boolean isUnauthorizedToken(AccessTokenDO accessTokenDO) {

        if (accessTokenDO.getAuthzUser() == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("There is no authorized user for access token id %s.",
                        accessTokenDO.getTokenId()));
            }
            return true;
        }
        return false;
    }

    /**
     * Decides whether the validation response is not applicable.
     *
     * @param validationResponse extracted decision of the XACML response
     * @return true if it is not applicable
     */
    private boolean isResponsePermit(String validationResponse) {
        return XACMLScopeValidatorConstants.RULE_EFFECT_PERMIT.equalsIgnoreCase(validationResponse);
    }

    /**
     * Decides whether the validation response is permit.
     *
     * @param validationResponse extracted decision of the XACML response
     * @return true if it is permit
     */
    private boolean isResponseNotApplicable(String validationResponse) {
        return XACMLScopeValidatorConstants.RULE_EFFECT_NOT_APPLICABLE.equalsIgnoreCase(validationResponse);
    }

    @Override
    public String getValidatorName() {
        return SCOPE_VALIDATOR_NAME;
    }

    private void createRowDTOForUserType(AuthenticatedUser authenticatedUser, List<RowDTO> rowDTOs) {

        String userType = null;
        if (authenticatedUser.isFederatedUser()) {
            userType = "FEDERATED";
        } else {
            userType = "LOCAL";
        }
        RowDTO userTypeDTO = createRowDTO(userType, XACMLScopeValidatorConstants.USER_TYPE_ID,
                XACMLScopeValidatorConstants.USER_CATEGORY);
        rowDTOs.add(userTypeDTO);
    }

    private void createRowDTOsForUserAttributes(AuthenticatedUser authenticatedUser,
                                                String action, List<RowDTO> rowDTOs, String token) {

        // User attributes are obtained from context. During token validation flow, if the user attributes are not
        // available, then authorization grant cache is used to get user attributes.
        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
        if (userAttributes.isEmpty()) {
            // UserAttributes can be null during token validation phase if OAuthCache expires.
            if (action.equals(XACMLScopeValidatorConstants.ACTION_VALIDATE)) {
                userAttributes = getUserAttributesFromAuthorizationGrantCache(token);
            }
        }
        if (userAttributes != null) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if (entry.getKey().getRemoteClaim() != null && StringUtils.isNotEmpty(entry.getKey().getRemoteClaim().
                        getClaimUri()) && StringUtils.isNotEmpty(entry.getValue())) {
                    if (entry.getKey().getRemoteClaim().getClaimUri().
                            equalsIgnoreCase(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR)) {
                        continue;
                    }
                    String userAttribute = entry.getValue();
                    String[] attributeValueList = null;
                    if (userAttribute.contains(FrameworkUtils.getMultiAttributeSeparator())) {
                        attributeValueList = getAttributeValues(userAttribute);
                    } else {
                        attributeValueList = new String[]{userAttribute};
                    }
                    for (String attributes : attributeValueList) {
                        String remoteClaimURI = entry.getKey().getRemoteClaim().getClaimUri();
                        // Creating XACML requestDTOs for each userattribute with attribute ID as mapped claim URI .
                        // If it is OIDC, claims are always in OIDC dialect, If it is OAuth, claims should be
                        // requested from service provider and will be in sp's requested claim dialect. That's why sp
                        // claim category is used.
                        RowDTO userClaims =
                                createRowDTO(attributes, remoteClaimURI,
                                        XACMLScopeValidatorConstants.SP_CLAIM_CATEGORY);
                        rowDTOs.add(userClaims);
                    }
                }
            }
        }
    }

    private Map<ClaimMapping, String> getUserAttributesFromAuthorizationGrantCache(String token) {

        Map<ClaimMapping, String> userAttributes = null;
        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(token);
        AuthorizationGrantCacheEntry cacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
        if (cacheEntry != null) {
            userAttributes = cacheEntry.getUserAttributes();

        }
        return userAttributes;
    }

    private String[] getAttributeValues(String attributes) {

        return attributes.split(FrameworkUtils.getMultiAttributeSeparator());
    }
}
