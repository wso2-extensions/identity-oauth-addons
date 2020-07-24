## Identity OAuth Addons 
This repository contains implementations for oauth extentions.

### 01. Private Key JWT Client Authentication 

Pre-requisites:

- Maven 3.x
- Java 1.7 or above

Tested Platform:

- Linux
- WSO2 IS 5.5.0
- Java 1.7

Do the following:

Deploying and Configuring JWT client-handler artifacts:
1. Execute "mvn clean install" to build the project.

2. Place component/client-handler/org.wso2.carbon.identity.oauth2.grant.jwttarget/
org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt-<version>-SNAPSHOT.jar in the <IS_HOME>/repository/component/dropins directory.

3. To register the JWT grant type, configure the <IS_HOME>/repository/conf/identity/identity.xml file by adding a new entry under the <OAuth><ClientAuthHandlers> element. Add a unique <ClientAuthHandler> identifier between as seen in the code block below.

        <EventListener type="org.wso2.carbon.identity.core.handler.AbstractIdentityHandler"
                                   name="org.wso2.carbon.identity.oauth2.token.handler.clientauth.jwt.PrivateKeyJWTClientAuthenticator"
                                   orderId="899" enable="true">
            <Property name="preventTokenReuse">true</Property>
            <Property name="RejectBeforeInMinutes">100</Property>
            <Property name="TokenEndPointAlias">sample url</Property>
        </EventListener>
            
4. Add Cache-configuration entry in <IS_HOME>/repository/conf/identity/identity.xml as below

        <CacheConfig>
           <CacheManager name="IdentityApplicationManagementCacheManager">
              ...
              <Cache name="PrivateKeyJWT" enable="true" timeout="10" capacity="5000" isDistributed="false"/>
           </CacheManager>
       </CacheConfig>
       
5. Restart Server
6. Add service provider
    - Select Add under Service Providers menu in the Main menu.
    - Fill in the Service Provider Name and provide a brief Description of the service provider.
    - Import the public key of the private_key_jwt issuer.
    - Expand the OAuth/OpenID Connect Configuration and click Configure.
    - Enter a callback url for example http://localhost:8080/playground2/oauth2client and click Add.
    - The OAuth Client Key and OAuth Client Secret will now be visible.

7. The cURL command below can be used to retrieve access token and refresh token using a JWT.
    ```curl -v POST -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" -k -d 'client_id=<clientid>&grant_type=authorization_code&code=$CODE&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=<private_key_jwt>&redirect_uri=http://localhost:8080/playground2/oauth2client" https://localhost:9443/oauth2/token```

8. Refer https://docs.wso2.com/display/IS550/Private+Key+JWT+Client+Authentication+for+OIDC for more details

### 02. Privileged User Authenticator

This authenticator is used to authenticate a privileged user and allow the permission to revoke accesstokens
 on behalf of an application.


**Deploying and Configuring  artifacts**
1. Execute "mvn clean install" to build the project.

2. Place component/org.wso2.carbon.identity.oauth2.clientauth.privilegeduser/target/
org.wso2.carbon.identity.oauth2.clientauth.privilegeduser-<version>-SNAPSHOT.jar in the
 <IS_HOME>/repository/component/dropins directory.
3.The cURL command below can be used to revoke an accesstoken.
 
 ```
 curl -k -v -d "username=<username>&password=<password>&token=<token>&token_type_hint
 =<token_type>&client_id=<client-id>"  -H "Content-Type: application/x-www-form-urlencoded" https
://localhost
:9443/oauth2/revoke
 ```

Sample Request:

```
curl -k -v -d "username=admin@abc.com&password=admin&token=9f716139-4493-3635-abec-7498c2e6cba8&token_type_hint
=access_token&client_id=9e8S8L1lkippHTPIwhfXSl6IWGUa"  -H "Content-Type: application/x-www-form-urlencoded" https://localhost:9443/oauth2/revoke
```

**Deployment.toml Config**

Add the following config in the deployment.toml file to enable this authenticator.
```
[[event_listener]]
id = "privileged_user_authenticator"
type = "org.wso2.carbon.identity.core.handler.AbstractIdentityHandler"
name = "org.wso2.carbon.identity.oauth2.clientauth.privilegeduser.PrivilegedUserAuthenticator"
order = "200"
```


**User Permission**

- The privileged user should have the following permission to revoke the access token `/permission/admin/manage
/application/revoke`
- Create the above permission
- Assign that permission to the privileged user

