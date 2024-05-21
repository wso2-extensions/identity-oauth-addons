## <p style="color: red; font-weight: bold;">⚠️ Deprecation Notice </p>

**This component has been moved to a new standalone repository.All the future development will be
continued in the new repository and this repository will no longer be maintained.**

**You can find the new repository here: [identity-oauth-dpop](https://github.com/wso2-extensions/identity-oauth-dpop)**


<hr style="border: 2px solid yellow;" />

# DPoP component

DPoP ( Demonstrating Proof of Possession ) is an additional security mechanism for the token
generation which overcomes the issue of bearer token which will not validate between who is
requested token and who is actually using the token for the access of a particular resource.The specification defines a mechanism to prevent illegal API calls from succeeding only with a stolen access token. In the traditional mechanism, API access is allowed only if the access token presented by the client application is valid

## Specification 
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-02

## Design 

### Sequence Diagram.

1. DPoP token request
![Screenshot from 2021-10-25 23-06-12](https://user-images.githubusercontent.com/26603378/138743329-5cc54271-08a6-44ec-938e-d675bdd24717.png)


2. Invoking protected APIs with DPoP token and DPoP proof.
![Invoke API(2)](https://user-images.githubusercontent.com/26603378/138742776-3d2c2714-c87e-4f77-9dce-24fde3df600e.jpeg)

### Sample client application to create dpop proof
PR : [wso2 /samples-is#302 ](https://github.com/wso2/samples-is/pull/302 )

### Deployment Instructions

1. Build the project using mvn clean install.
2. Add the  org.wso2.carbon.identity.dpop-2.4.3-SNAPSHOT.jar JAR into the <IS_HOME>/repository/components/dropins folder.
3. Add the below configuration to deployment.toml file.

 ```
[[event_listener]]
id = "dpop_listener"
type = "org.wso2.carbon.identity.core.handler.AbstractIdentityHandler"
name="org.wso2.carbon.identity.dpop.listener.OauthDPoPInterceptorHandlerProxy"
order = 13
enable = true
properties.header_validity_period = 90
properties.skip_dpop_validation_in_revoke = "true"

[[oauth.custom_token_validator]]
type = "dpop"
class = "org.wso2.carbon.identity.dpop.validators.DPoPTokenValidator"
```
4. Restart the Identity Server.
5. Sign in to the Management Console and navigate to
   ```Service Providers -> List -> Edit -> Inbound Authentication Configuration ->OAuth OpenID Connect Configuration -> Edit```
6. Enable DPoP Based Access token binding type and Validate token bindings.

![Screenshot from 2021-10-25 23-08-05](https://user-images.githubusercontent.com/26603378/138743547-c6d71a23-e654-463b-9650-2cebdf37268d.png)

### Sample Usage Instructions

1. Access Token from Password :

```
curl --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'dpop: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IlJTMzg0IiwiandrIjp7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6ImgyNlFBSUQtQWhyTmdac2FyX1pmUzM2aUtrTVQ0ZWR2YVJ3eHBheVFSVUlyV29qdENtZ0tCUnRXSllzSmJfQmJ5ZWJnb3gxVXhnaHRjMWNGVFFueVF6aDNHTHRfZXh5ajJ5Y2lFRHhUVTgyTHllT2ZaTnpVQTF0cjBPOFNtdVp4NWxSNnZKYTlMSFFYLXNYdFRsNVBMOWpHNDJVeENnZ3VETG5EZzJUcUMtWmNmdnItMER0OXFJNS1CdVo0TmZTQmE3WlBFeGZ0d2RuemVnRHJOemlfbEFDM0drRUs4dmdHYjFDc0hVS0dUdXZsX0MzX2JtVU50ZzdVdURYdEVyQmRxOHlxc0NHQ3lzSGs5YlBodkZ1bXJaQS1lU0pEQTlpMFYzOUJnaTZUYUpqNU5PZ0hkUFVET0lmUzF6aXE5WlVNR0NRdlJuN3hsN2N2X01MTUNTVElhdyJ9fQ.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNjMyNzUzODQwLCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJpYXQiOjE2MzI3NTM4NDAsImp0aSI6IjE2MGVlYjIwLTVjN2EtNDM4ZC05YmI2LTY5ZTY0ZmU2N2ZjYiJ9.IMTqfcHtrlyJM9NqSuVulN2n2yWDgHkzRroxDF764HZrfThoJHp6YAx9PnSRjb652I5agZy48UZehKUiQ-tIXvW-vU8-C_3oeaOIMbTrXKDPHh41_1udw3B_zNkdwOPlyyNgFFRk_vzcV7yV7JdLaJVmMKmbNcqWE5zj7SbvorXhIzhVTL0XKhC1RzcuGImJYwzEUsAp0EWKHmD5Io46WQgY_Qauqzlyat2NYp797yySjfsIXxtFhlv_dsnMwBG4_-qWuwKCWLbUS1dEctwpv3cRqmt3L1ICQK7-t6CorhKy3MxWn7uM0viM7Jm0tjZbz3PYl5aDA55bqUAst9IlsQ' \
--header 'Authorization: Basic ajdPOWVqbmpUSUN1VFl4cGMwamQ4MjJvU2FjYTpmREJzSXB5djlYS1lOVUxfQWs1QTM0NFh6cUVh' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=admin' \
--data-urlencode 'password=admin' \
--data-urlencode 'scope=openid internal_user_mgt_list'
```

&emsp;&ensp;Sample Response:

```
{
    "access_token": "1ce0fc0a-c830-307a-aafc-d25fdc4063ee",
    "refresh_token": "ff7a6adb-116d-3a6f-83ff-3f61c7fa8b2f",
    "scope": "internal_user_mgt_list openid",
    "id_token": "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlRBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoiUGw2ZjJvdWNmY3RnQ2ZLazJZOEZ5USIsImF1ZCI6IjVEb09HWkFHQV9sQUdnSDB2WkJSRTgzTl9sQWEiLCJzdWIiOiJhZG1pbiIsIm5iZiI6MTY1Mjc2ODc5MiwiYXpwIjoiNURvT0daQUdBX2xBR2dIMHZaQlJFODNOX2xBYSIsImFtciI6WyJwYXNzd29yZCJdLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE2NTI3NzIzOTIsImlhdCI6MTY1Mjc2ODc5Mn0.dCwn5ln-iROxbVVOJicQFFqLse8NOYXc_HVnhCiQPoBLShaXKi-NbnTvXwoFL1NxQhv96YgyUhjrkLoQDEmzxQnFMkgq3hJV0MH68SBpsCaKIIzg3Z0KT_5VFSvDC-bQGHfmGS-Gxf5TWkKT7FGke-OYUw_x940qy_PMfZOM-q4A9gBiPTazjXbGo0dkIOINnEfz6TQvrE2opJxV7dj3bGV4NT-3Vqj3ooNbruQrK-c6ir_LLoyA71yuPJhkmtT8Ae_mXSDBjuH-TxcXp_htoGbCb_xDgA3zRyRmvc8OSlaHAO-OhtNK_d6x-wiUjM-n0hMdvGNS4oPn1yHyy5WEsg",
    "token_type": "DPoP",
    "expires_in": 3600
}
```

2. Access Token from Refresh Token :

```
curl --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'dpop: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibkNmX3lscldjMTVtejVJZWxSQmJ2TGhLbFV1em4zd1dDSW9ReHVOUThlVSIsInkiOiJhMmU3OTU3S2c3aTVxTUE5UHVpandmSE9nMk95QlRsZ0pVaEhzWGtNaGZnIn19.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNjUyMzY5ODE5LCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJpYXQiOjE2NTIzNjk4MTksImp0aSI6IjVhOWY0NDI5LWU2ZDMtNGE3NS1iZTU4LTViOTZhZGY4MTcyZiJ9.DIwqvVuG_JZYM1dOGha6CANCM4RUC-5MQQkYsbTDKJfMpgR8akYoOSQigDpPMJqbrQFqXq6FXQoPOEJVqlMiqA' \
--header 'Authorization: Basic NURvT0daQUdBX2xBR2dIMHZaQlJFODNOX2xBYTpaZjl5U3pCUzRPZ3M0eWtuMWJaZmxVZkExTXNh' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=a8dcd0c4-7272-3901-ade2-d24cb8bae241'
```

3. Access Protected Resource :

```
curl --location --request GET 'https://localhost:9443/scim2/Users' \
--header 'accept: application/scim+json' \
--header 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibkNmX3lscldjMTVtejVJZWxSQmJ2TGhLbFV1em4zd1dDSW9ReHVOUThlVSIsInkiOiJhMmU3OTU3S2c3aTVxTUE5UHVpandmSE9nMk95QlRsZ0pVaEhzWGtNaGZnIn19.eyJodG0iOiJHRVQiLCJzdWIiOiJzdWIiLCJuYmYiOjE2NTI3Njg4MzEsImlzcyI6Imlzc3VlciIsImh0dSI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvc2NpbTJcL1VzZXJzIiwiaWF0IjoxNjUyNzY4ODMxLCJqdGkiOiJlYjExOWZhYS02OGM2LTQ2ZGYtYTE2Ny1iZDAwNTJhYzRhYWEifQ.h5oujqZugEANfOnEWM23z6AGpcckic4fphkcjGqrizy9_K7pybYtadGBxYlrU81d0bP5LKbkZCKXWtdvYXLqXg' \
--header 'Authorization: DPoP 1ce0fc0a-c830-307a-aafc-d25fdc4063ee'
```
&emsp;&ensp;Here, **Authorization Header Value = DPoP {access-token}**

4. Revoke Token :

```
curl --location --request POST 'https://localhost:9443/oauth2/revoke' \
--header 'Content-Type: application/x-www-form-urlencoded;charset=UTF-8' \
--header 'DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibkNmX3lscldjMTVtejVJZWxSQmJ2TGhLbFV1em4zd1dDSW9ReHVOUThlVSIsInkiOiJhMmU3OTU3S2c3aTVxTUE5UHVpandmSE9nMk95QlRsZ0pVaEhzWGtNaGZnIn19.eyJodG0iOiJQT1NUIiwic3ViIjoic3ViIiwibmJmIjoxNjUyNzY4NjczLCJpc3MiOiJpc3N1ZXIiLCJodHUiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvcmV2b2tlIiwiaWF0IjoxNjUyNzY4NjczLCJqdGkiOiI4OGIzNzBjNS1kYWVmLTQyOWItOTJjNS1iMGFhOTMzOGU1NTQifQ.6qa7IwHY1_xwykRSHRgxABOtBdPkp_nKDKSvCZ_C9GRWZaNtwKJsIwBmlFOYwnzh_yM3HsZj9HaGCBrNZfJ5fQ' \
--header 'Authorization: Basic NURvT0daQUdBX2xBR2dIMHZaQlJFODNOX2xBYTpaZjl5U3pCUzRPZ3M0eWtuMWJaZmxVZkExTXNh' \
--data-urlencode 'token=1ce0fc0a-c830-307a-aafc-d25fdc4063ee' \
--data-urlencode 'token_type_hint=access_token'
```


