package org.wso2.carbon.identity.dpop.listener;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axiom.om.OMElement;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.dpop.util.OuthTokenType;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import javax.ws.rs.HttpMethod;
import javax.xml.namespace.QName;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

/**
 * This class extends AbstractOAuthEventInterceptor and listen to oauth related events. In this class, dpop proof validation
 * will be handle for dpop type token requests
 */
public class OauthDPoPInterceptorHandlerProxy extends AbstractOAuthEventInterceptor {
    private static final Log log = LogFactory.getLog(OauthDPoPInterceptorHandlerProxy.class);
    private int dPopValidity;
    private boolean isDPoPConfigEnable;

    /**
     * This method handles dpop proof validation during pre token issuance.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the pre token issue event with the DPoP proof for the " +
                    "application: %s", tokenReqDTO.getClientId()));
        }
        String dPopProof=getDPoPHeader(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders());

        if(!StringUtils.isBlank(dPopProof)){
            /*
             * if the DPoP proof is provided then it will be handle as DPoP token request
             */
            if(!dPoPValidation(dPopProof,tokReqMsgCtx)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP proof validation failed, Application ID: " + tokenReqDTO.getClientId());
                }
                throw new IdentityOAuth2Exception("DPoP validation failed");
            }
        }else{
            /*
             * As there is no DPoP Proof It will be handled as Bearer token request
             */
            if (log.isDebugEnabled()) {
                log.debug("Bearer access token request received from: " + tokenReqDTO.getClientId());
            }

        }
    }

    /**
     * This method handles dpop proof validation during pre token renewal.
     *
     * @param tokenReqDTO  OAuth2AccessTokenReqDTO.
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @param params       Map of parameters.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug(String.format("Listening to the pre token renewal event with the DPoP proof for the " +
                    "application: %s", tokenReqDTO.getClientId()));
        }
        String dPopProof=getDPoPHeader(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders());

        if(!StringUtils.isBlank(dPopProof)){
            /*
             * if the DPoP proof is provided then it will be handle as DPoP token request
             */
            if(!dPoPValidation(dPopProof,tokReqMsgCtx)) {
                if (log.isDebugEnabled()) {
                    log.debug("DPoP proof validation failed, Application ID: " + tokenReqDTO.getClientId());
                }
                throw new IdentityOAuth2Exception("DPoP validation failed");
            }
        }else{
            /*
             * As there is no DPoP Proof It will be handled as Bearer token request
             */
            if (log.isDebugEnabled()) {
                log.debug("Bearer access token renewal request received from: " + tokenReqDTO.getClientId());
            }
        }
    }

    @Override
    public boolean isEnabled() {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ||
                Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }
    private boolean dPoPValidation(String dPopProof,OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        /**
         *  2.  Is DPoP header-formed JWT
         *  3. all required claims are contained in the JWT,
         *  4. signature validation using extracted public key (JWK)
         */
        try {
            Timestamp currentTimestamp = new Timestamp(new Date().getTime());
            SignedJWT signedJwt = SignedJWT.parse(dPopProof);
            JWSHeader header = signedJwt.getHeader();
            dPoPHeaderCheck(header);
            dPoPPayloadCheck(signedJwt.getJWTClaimsSet(),currentTimestamp);
            return isValidSignature(header.getJWK().toString(),signedJwt, tokReqMsgCtx);

        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Invalid DPoP Header");
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception(e.getMessage());
        }
    }

    private boolean isValidSignature(String jwk,SignedJWT signedJwt,OAuthTokenReqMessageContext tokReqMsgCtx)
            throws ParseException, JOSEException {
        JWK parseJwk = JWK.parse(jwk);
        TokenBinding tokenBinding = new TokenBinding();
        tokenBinding.setBindingType("DPoP");
        tokenBinding.setBindingReference("CNF");
        boolean validSignature = false;
        if("EC".equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))) {
            ECKey ecKey = (ECKey) parseJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();
            validSignature =verifySignatureWithPublicKey(new ECDSAVerifier(ecPublicKey),signedJwt);
            if(validSignature){
                String publicKey = computeThumbprintOfECKey(ecKey);
                tokenBinding.setBindingValue(publicKey);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(publicKey));
            }
        } else if("RSS".equalsIgnoreCase(String.valueOf(parseJwk.getKeyType()))){
            RSAKey rsaKey = (RSAKey) parseJwk;
            RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
            validSignature =verifySignatureWithPublicKey(new RSASSAVerifier(rsaPublicKey),signedJwt);
            if(validSignature){
                String publicKey = computeThumbprintOfRSAKey(rsaKey);
                tokenBinding.setBindingValue(publicKey);
                tokenBinding.setBindingReference(DigestUtils.md5Hex(publicKey));
            }
        }
        tokReqMsgCtx.setTokenBinding(tokenBinding);
        return validSignature;
    }

    private void dPoPHeaderCheck(JWSHeader header)throws IdentityOAuth2Exception{
        if(header.getJWK()==null){
            throw new IdentityOAuth2Exception("DPoP proof header is not found");
        }
        JWSAlgorithm algorithm = header.getAlgorithm();
        if(algorithm==null){
            throw new IdentityOAuth2Exception("DPoP Proof validation failed, Encryption algorithm is not found");
        }
        if(!"dpop+jwt".equalsIgnoreCase(header.getType().toString())){
            throw new IdentityOAuth2Exception("Invalid DPoP type");
        }
    }

    private String computeThumbprintOfRSAKey(RSAKey rsaKey) throws JOSEException {
        RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
        return rsaKey.computeThumbprint().toString();
    }

    private String computeThumbprintOfECKey(ECKey ecKey) throws JOSEException {
        ECPublicKey ecPublicKey = ecKey.toECPublicKey();
        return ecKey.computeThumbprint().toString();

    }
    private boolean verifySignatureWithPublicKey(JWSVerifier jwsVerifier, SignedJWT signedJwt) throws JOSEException {
        return signedJwt.verify(jwsVerifier);
    }

    private void dPoPPayloadCheck(JWTClaimsSet jwtClaimsSet,Timestamp currentTimestamp)throws IdentityOAuth2Exception{
        if(jwtClaimsSet==null){
            throw new IdentityOAuth2Exception("DPoP proof payload is invalid");
        }else{
           if(jwtClaimsSet.getClaim("htm")== null || !HttpMethod.POST.equalsIgnoreCase(jwtClaimsSet.getClaim("htm").toString())){
               throw new IdentityOAuth2Exception("Invalid DPoP Proof Payload");
           }
            if(jwtClaimsSet.getClaim("htu")==null){
                throw new IdentityOAuth2Exception("Invalid DPoP Proof Payload");
            }
            if(jwtClaimsSet.getClaim("iat")==null){
                throw new IdentityOAuth2Exception("Invalid DPoP Proof Payload");
            }

            Date issueAt = (Date) jwtClaimsSet.getClaim("iat");
            issueAt.getTime();

            IdentityConfigParser configParser = IdentityConfigParser.getInstance();
            OMElement oauthElem = configParser.getConfigElement("OAuth");
            getDPoPConfig(oauthElem);
            if(((currentTimestamp.getTime()-issueAt.getTime())/1000)>dPopValidity){
                if (log.isDebugEnabled()) {
                    log.debug("DPoP Proof expired");
                }
                throw new IdentityOAuth2Exception("Expired DPoP Proof Payload");
            }
        }
    }
    private void getDPoPConfig(OMElement oauthElem ){
        OMElement dPopConfigElem = oauthElem
                .getFirstChildWithName(getQNameWithIdentityNS("DPoPConfig"));
        if (dPopConfigElem != null) {
            isDPoPConfigEnable =true;
            OMElement tokenCleanupConfigElem =
                    dPopConfigElem.getFirstChildWithName(getQNameWithIdentityNS("HeaderValidity"));
            if (tokenCleanupConfigElem != null && StringUtils.isNotBlank(tokenCleanupConfigElem.getText())) {
                dPopValidity = Integer.parseInt(tokenCleanupConfigElem.getText().trim());

            } else {
                dPopValidity = 60;
                isDPoPConfigEnable = false;
            }
        } else {
            isDPoPConfigEnable = false;
        }
    }

    private QName getQNameWithIdentityNS(String localPart) {
        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, localPart);
    }

    private String getDPoPHeader(HttpRequestHeader[] httpRequestHeaders){
        for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
            if (OuthTokenType.DPOP.name().equalsIgnoreCase(httpRequestHeader.getName())){
                return httpRequestHeader.getValue()[0];
            }
        }
        return null;
    }
}
