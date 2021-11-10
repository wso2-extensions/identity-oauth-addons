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
2. Add the  org.wso2.carbon.identity.dpop-2.4.3-SNAPSHOT.jar JAR into the <IS_HOME>/repository/components/droppings folder.
3. Add the below configuration to deployment.toml file.

 ```
[[event_listener]]
id = "dpop_listener"
type = "org.wso2.carbon.identity.core.handler.AbstractIdentityHandler"
name="org.wso2.carbon.identity.dpop.listener.OauthDPoPInterceptorHandlerProxy"
order = 13
enable = true
properties.header_validity_period = 90

[[oauth.custom_token_validator]]
type = "dpop"
class = "org.wso2.carbon.identity.dpop.validators.DPoPTokenValidator"

[oauth.grant_type.uma_ticket]
retrieve_uma_permission_info_through_introspection = true
```
4. Restart the Identity Server.
5. Sign in to the Management Console and navigate to
   ```Service Providers -> List -> Edit -> Inbound Authentication Configuration ->OAuth OpenID Connect Configuration -> Edit```
6. Enable DPoP Based Access token binding type and Validate token bindings.

![Screenshot from 2021-10-25 23-08-05](https://user-images.githubusercontent.com/26603378/138743547-c6d71a23-e654-463b-9650-2cebdf37268d.png)

Sample dpop token request :
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

Response:

```
{
    "access_token": "fbf01348-3e34-3644-a6f3-eebace38fc1b",
    "refresh_token": "408ee317-bd4a-388e-bc85-c558bdd7b578",
    "scope": "internal_user_mgt_list openid",
    "id_token": "eyJ4NXQiOiJNell4TW1Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTXpVMlpHVmxOZyIsImtpZCI6Ik16WXhNbUZrT0dZd01XSTBaV05tTkRjeE5HWXdZbU00WlRBM01XSTJOREF6WkdRek5HTTBaR1JsTmpKa09ERmtaRFJpT1RGa01XRmhNelUyWkdWbE5nX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoiRHBUbjRYbjFYNjdkdGtES1JIeHFyQSIsImF1ZCI6Imo3Tzllam5qVElDdVRZeHBjMGpkODIyb1NhY2EiLCJzdWIiOiJhZG1pbiIsIm5iZiI6MTYzMjc1NDAzMSwiYXpwIjoiajdPOWVqbmpUSUN1VFl4cGMwamQ4MjJvU2FjYSIsImFtciI6WyJwYXNzd29yZCJdLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE2MzI3NTc2MzEsImlhdCI6MTYzMjc1NDAzMX0.COAX5moYElnEBl-KRd81GokgtCq8ENz4gHMqdupXff8TW1Xt2GEqahBDxwuk1kQA7Z-pRfIvm-UJ8_h0SHKjf3670FKt6oSwEAVLeJ_esdtFmAbrq-hbnPvp1SVAIfhUp9q3sGT_c6YsU8MTkyIz8BDfl0JHwU26364GO37tHXJ40kTxHVZ8pTHwZj-yVFY1OdPSCsioYd7f3ukh9YWxPrBYsPcvPzSrORfUpzY6U5OmSa4w4YVqLUzVCCZ1qEK2Zk1pPn_w6-vgYt2i7pMWcu3I4pSFfo9E1W89dp4Y2oVFB7rAiH4x0GNoPCmhCWYFIYHRKmcQ1n2sUNZSIn1KsQ",
    "token_type": "DPoP",
    "expires_in": 3477
}
```


