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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil.JAVAX_SERVLET_REQUEST_CERTIFICATE;

@WithCarbonHome
@PrepareForTest({OAuth2Util.class, HttpServletRequest.class, MutualTLSUtil.class})
public class MutualTLSClientAuthenticatorTest extends PowerMockTestCase {

    private MutualTLSClientAuthenticator mutualTLSClientAuthenticator = new MutualTLSClientAuthenticator();
    private static String CLIENT_ID = "someclientid";
    private static String CERTIFICATE_CONTENT =
            "MIIDmzCCAoOgAwIBAgIJAJuzH6NrV5s5MA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV" +
            "BAYTAlNMMQswCQYDVQQIDAJXUDEQMA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwE\n" +
            "d3NvMjENMAsGA1UECwwEd3NvMjEYMBYGA1UEAwwPdHJhdmVsb2NpdHkuY29tMB4X\n" +
            "DTE4MDIwNjEwNTk1N1oXDTE5MDIwNjEwNTk1N1owZDELMAkGA1UEBhMCU0wxCzAJ\n" +
            "BgNVBAgMAldQMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQKDAR3c28yMQ0wCwYD\n" +
            "VQQLDAR3c28yMRgwFgYDVQQDDA90cmF2ZWxvY2l0eS5jb20wggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDlKn3dmaLW7iBOKdlWY8Go8Q7kR6HNY/8j0arv\n" +
            "EcZYqMrihcSX5i5Mz57t6Z3xpaGay2jPWND7dDA/RocircleBKQk0X2OxoEYba3W\n" +
            "t477EpN9RWGAZuuANUSVKjC8FsNYhEp9y59IuxK+IgDAEfR8O2RNLYA6O3UjBC/R\n" +
            "f443CwOE4jFm3eVAeLIBudn/viC56rPBozVX4DxPaHIzxocfK6EpDljEG4lJ7otS\n" +
            "SbIpPlmAO/0f8F1Q6syv+sCkPRGn/OjTXWtUg6QXAclguOCl3MI+pLMThQUATcKb\n" +
            "2QkPl8r8/b/S8qMRKzSVYyjNP+CsDRO/MdlC50QZSJBaNYqdAgMBAAGjUDBOMB0G\n" +
            "A1UdDgQWBBSIXyhWV6Ac+FiqdXEeQwqzJfFLhDAfBgNVHSMEGDAWgBSIXyhWV6Ac\n" +
            "+FiqdXEeQwqzJfFLhDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBQ\n" +
            "S2jmfzF8x1iwmRqXILZ6qkF5ABAlNa3Z3bMFB7uErw2BxASMOLWfjZdEcyICDGIf\n" +
            "ZeYchqEPTvv/RIqDlu8xda3N2kRp1un5Hfffavm6ZWR3J8LdsnSjrehZ/afxuy8a\n" +
            "OFKiRtj9tqpG3C/s/NBJ9Gl4u5YhihOSJG9ELihJSxWDYI641AOalWnUQ/SxfeCO\n" +
            "TY75aViCAD6QDmBxe/opQYExBdgNOCQ6HdP5WWBT6EEggBe/mqOM/dchj57rpPtw\n" +
            "IOQjy9UCaY7tq4SmhAJyab0mxjcFoRBpzOJIDh+N8ozSDK+MepyFSwtW5zVacOiG\n" +
            "OQUrBTGXQFZOGKje8sbS";

    private static String TEST_JSON_WITH_X5T ="{\n" +
            "  \"keys\" : [ {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"xd_gJKFwSqB0XbB8mq15S7Sv5WnZyQFHjFZBDLEpUHJV5UaGIVl652LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5t\" : \"RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"tpqKoJfFLhDAfBgNVHSM=\"\n" +
            "  }, {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"M2maFm3VYlMBOn3GetVWGXkrKrk\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"p_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWKA-63zmjr1OAI2IDx5R6krlY6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" +
            "    \"use\" : \"sig\",\n" +
            "    \"x5t\" : \"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/M2maFm3VYlMBOn3GetVWGXkrKrk.pem\",\n" +
            "    \"x5t#S256\" : \"M2maFm3VYlMBOn3GetVWGXkrKrk\"\n" +
            "  } ]\n" +
            "}";

    private static String TEST_JSON_WITH_X5C ="{\n" +
            "  \"keys\" : [ {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"RjM3REY1MEVFMUQ2MTZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"x_AfraZx04boy30iEHUAupKqq4hnjE4APFj1pLrs55QGDoTgSuTRw2xIzMSVjcUREM-UZFBlOXduL2B1SiYQdT8ctprJRZPvOkYZyUoYLPg9n1pEp_CVYeYhV71gLUmCmrUe52LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5c\" : [ "
            + "\"MIIFODCCBCCgAwIBAgIEWcVdrDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFByZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMTgxMjA1MDMwMjU4WhcNMjAwMTA1MDMzMjU4WjBhMQswCQYDVQQGEwJHQjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxGzAZBgNVBAsTEjAwMTU4MDAwMDFIUVFyWkFBWDEfMB0GA1UEAxMWMlgwMXRUTEQwaEJtd2pFZ1dWakd2ajCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMfwH62mcdOG6Mt17Yu6D1zBItemYl1iIhcunIv76UChKhl7WyivNouvGWhww+hLxK0fAwnOkGsCuQBnf4CShcEqgdF2wfJqteUu0r+Vp2ckBR4xWQQyxKVByVeVGhiFZetIhB1ALqSqquIZ4xOADxY9aS67OeUBg6E4Erk0cNsSMzElY3FERDPlGRQZTl3bi9gdUomEHU/HLaayUWT7zpGGclKGCz4PZ9aRKfwlWHmIVe9YC1Jgpq1Hudiz/kxEb45O4BdenPFAlU+xuMbc1sNYSbXNXgweb+jbMaVka+Y9helXUbzf/8LkUYJZjdRncNN/WbxBnQrfkhJ1Z+HaVbkCAwEAAaOCAgQwggIAMA4GA1UdDwEB/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgeAGA1UdIASB2DCB1TCB0gYLKwYBBAGodYEGAWQwgcIwKgYIKwYBBQUHAgEWHmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9wb2xpY2llczCBkwYIKwYBBQUHAgIwgYYMgYNVc2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBPcGVuQmFua2luZyBSb290IENBIENlcnRpZmljYXRpb24gUG9saWNpZXMgYW5kIENlcnRpZmljYXRlIFByYWN0aWNlIFN0YXRlbWVudDBtBggrBgEFBQcBAQRhMF8wJgYIKwYBBQUHMAGGGmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9vY3NwMDUGCCsGAQUFBzAChilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNydDA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vb2IudHJ1c3Rpcy5jb20vb2JfcHBfaXNzdWluZ2NhLmNybDAfBgNVHSMEGDAWgBRQc5HGIXLTd/T+ABIGgVx5eW4/UDAdBgNVHQ4EFgQUwA+9otHiTEen8wHnnuitXR3ZuFowDQYJKoZIhvcNAQELBQADggEBADvRik60g4F43y8YMof/Ukle3pMuRUQlIe+Nk5LXbwcOI5iMZ0h768LbmqZRqN/yRUcvAeZFXE92O59iDWbVm2zTKvGaQaUwowvi9JuH2CTLQfW5+shmvEyJnRqf2mCpJWyh4W0JgckZwtljSYR0AsNnbjNhTE86MyaRZ1Uuun2fbNfQskKHb3bkPJcRkMfplGN5Y/uNFwnanfGnoACoMtimgWB2AD9i3cLowik5GGPtu7QGd3GFJaPnSLbV8vFxt/OBrF5fpBptCDvvN0aV9HYMlVRNiJrSJyc7kzEllNmCQR7GoyFzjnWJ2cMNp86CME/FRqNgaEAwV84x6i7W0xE=\" ],\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" +
            "  }, {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"p5KzjtKkBSJRtWAmS5uekysz9Ax93ziIq-mz_0Z65Lc6EtyE9O2PO5ED5fWt8_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWKA-63zmjr1OAI2IDx5R6krlY6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" +
            "    \"use\" : \"sig\",\n" +
            "    \"x5c\" : [ "
            + "\"MIIDmzCCAoOgAwIBAgIJAJuzH6NrV5s5MA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNVBAYTAlNMMQswCQYDVQQIDAJXUDEQMA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwE\n" +
            "d3NvMjENMAsGA1UECwwEd3NvMjEYMBYGA1UEAwwPdHJhdmVsb2NpdHkuY29tMB4X\n" +
            "DTE4MDIwNjEwNTk1N1oXDTE5MDIwNjEwNTk1N1owZDELMAkGA1UEBhMCU0wxCzAJ\n" +
            "BgNVBAgMAldQMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQKDAR3c28yMQ0wCwYD\n" +
            "VQQLDAR3c28yMRgwFgYDVQQDDA90cmF2ZWxvY2l0eS5jb20wggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDlKn3dmaLW7iBOKdlWY8Go8Q7kR6HNY/8j0arv\n" +
            "EcZYqMrihcSX5i5Mz57t6Z3xpaGay2jPWND7dDA/RocircleBKQk0X2OxoEYba3W\n" +
            "t477EpN9RWGAZuuANUSVKjC8FsNYhEp9y59IuxK+IgDAEfR8O2RNLYA6O3UjBC/R\n" +
            "f443CwOE4jFm3eVAeLIBudn/viC56rPBozVX4DxPaHIzxocfK6EpDljEG4lJ7otS\n" +
            "SbIpPlmAO/0f8F1Q6syv+sCkPRGn/OjTXWtUg6QXAclguOCl3MI+pLMThQUATcKb\n" +
            "2QkPl8r8/b/S8qMRKzSVYyjNP+CsDRO/MdlC50QZSJBaNYqdAgMBAAGjUDBOMB0G\n" +
            "A1UdDgQWBBSIXyhWV6Ac+FiqdXEeQwqzJfFLhDAfBgNVHSMEGDAWgBSIXyhWV6Ac\n" +
            "+FiqdXEeQwqzJfFLhDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBQ\n" +
            "S2jmfzF8x1iwmRqXILZ6qkF5ABAlNa3Z3bMFB7uErw2BxASMOLWfjZdEcyICDGIf\n" +
            "ZeYchqEPTvv/RIqDlu8xda3N2kRp1un5Hfffavm6ZWR3J8LdsnSjrehZ/afxuy8a\n" +
            "OFKiRtj9tqpG3C/s/NBJ9Gl4u5YhihOSJG9ELihJSxWDYI641AOalWnUQ/SxfeCO\n" +
            "TY75aViCAD6QDmBxe/opQYExBdgNOCQ6HdP5WWBT6EEggBe/mqOM/dchj57rpPtw\n" +
            "IOQjy9UCaY7tq4SmhAJyab0mxjcFoRBpzOJIDh+N8ozSDK+MepyFSwtW5zVacOiG\n" +
            "OQUrBTGXQFZOGKje8sbS\" ],\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/dn/viC56rPBozVX4DxPaHIzxocfK.pem\",\n" +
            "    \"x5t#S256\" : \"JfFLhDAfBgNVHSM\"\n" +
            "  } ]\n" +
            "}";

    private static String TEST_JSON ="{\n" +
            "  \"keys\" : [ {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"x_AfraZx04boy3Xti7oPXMEi16ZiXWIiFy6ciFHjFZBDLEpUHJV5UaGIVl60iEHUAupKqq4hnjE4APFj1pLrs55QGDoTgSuTRw2xIzMSVjcUREM-UZFBlOXduL2B1SiYQdT8ctprJRZPvOkYZyUoYLPg9n1pEp_CVYeYhV71gLUmCmrUe52LP-TERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n" +
            "    \"use\" : \"tls\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" +
            "  }, {\n" +
            "    \"e\" : \"AQAB\",\n" +
            "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" +
            "    \"kty\" : \"RSA\",\n" +
            "    \"n\" : \"PO5ED5fWt8_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKILo570RR7GThgLwmWNWAWK6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdRxKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" +
            "    \"use\" : \"sig\",\n" +
            "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMTYzQTk5MTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n" +
            "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" +
            "  } ]\n" +
            "}";


    @DataProvider(name = "testAuthenticateClientWhenJWKSEndPointGiven")
    public Object[][] testAuthenticateClientWhenJWKSEndPointGiven() {

        Map<String, List> bodyParamsWithClientId = new HashMap<>();
        List<String> clientIdList = new ArrayList<>();
        clientIdList.add(CLIENT_ID);
        bodyParamsWithClientId.put(OAuth.OAUTH_CLIENT_ID, clientIdList);

        return new Object[][] {

                {
                        getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(),
                        buildOAuthClientAuthnContext(CLIENT_ID), true, TEST_JSON_WITH_X5C
                },

                {
                        getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId,
                        buildOAuthClientAuthnContext(CLIENT_ID), true, TEST_JSON_WITH_X5T
                },

                {
                        getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId,
                        buildOAuthClientAuthnContext(CLIENT_ID), false, TEST_JSON
                },
                };

    }

    @DataProvider(name = "testClientAuthnData")
    public Object[][] testClientAuthnData() {

        Map<String, List> bodyParamsWithClientId = new HashMap<>();
        List<String> clientIdList = new ArrayList<>();
        clientIdList.add(CLIENT_ID);
        bodyParamsWithClientId.put(OAuth.OAUTH_CLIENT_ID, clientIdList);

        return new Object[][]{

                // Correct  client certificate present with client Id in request body.
                {getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(), buildOAuthClientAuthnContext(CLIENT_ID), true},

                // Correct  client certificate present with client Id in request body.
                {getCertificate(CERTIFICATE_CONTENT), bodyParamsWithClientId, buildOAuthClientAuthnContext(CLIENT_ID), true},

                // Correct client certificate not provided.
                {null, new HashMap<String, List>(), buildOAuthClientAuthnContext(null), false},
        };
    }

    @Test(dataProvider = "testClientAuthnData")
    public void testAuthenticateClient(Object certificate, HashMap<String, List> bodyContent,
                                       Object oAuthClientAuthnContextObj, boolean authenticationResult) throws
            Exception {

        PowerMockito.mockStatic(OAuth2Util.class);
        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);

        PowerMockito.when(OAuth2Util.getTenantDomainOfOauthApp(Matchers.anyString())).thenReturn("carbon.super");
        PowerMockito.when(OAuth2Util.getX509CertOfOAuthApp(oAuthClientAuthnContext.getClientId(), "carbon.super")).thenReturn
                (getCertificate(CERTIFICATE_CONTENT));
        PowerMockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn
                (certificate);
        assertEquals(mutualTLSClientAuthenticator.authenticateClient(httpServletRequest, bodyContent,
                oAuthClientAuthnContext), authenticationResult, "Expected client authentication result was not " +
                "received");
    }

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                {getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(), false},
                {null, getBodyContentWithClientId(CLIENT_ID), false},
                {getCertificate(CERTIFICATE_CONTENT), getBodyContentWithClientId(CLIENT_ID), true},
        };
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(X509Certificate certificate, HashMap<String, List> bodyContent, boolean canHandle)
            throws
            Exception {

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        PowerMockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn(certificate);
        assertEquals(mutualTLSClientAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @Test
    public void testGetName() throws Exception {

        assertEquals("MutualTLSClientAuthenticator", mutualTLSClientAuthenticator.getName(), "Mutual " +
                "TLS client authenticator name has changed.");
    }

    @DataProvider(name = "testGetClientIdData")
    public Object[][] testGetClientIdData() {

        return new Object[][]{

                // Not client Id found in request body.
                {new HashMap<String, List>(), null},

                // Valid client Id in request body.
                {getBodyContentWithClientId(CLIENT_ID), CLIENT_ID},
        };
    }

    @Test(dataProvider = "testGetClientIdData")
    public void testGetClientId(HashMap<String, List> bodyContent, String clientId) throws Exception {

        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);
        assertEquals(mutualTLSClientAuthenticator.getClientId(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), clientId);
    }

    private OAuthClientAuthnContext buildOAuthClientAuthnContext(String clientId) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        return oAuthClientAuthnContext;
    }

    private X509Certificate getCertificate(String certificateContent) {

        if (StringUtils.isNotBlank(certificateContent)) {
            // Build the Certificate object from cert content.
            try {
                return (X509Certificate) IdentityUtil.convertPEMEncodedContentToCertificate(certificateContent);
            } catch (CertificateException e) {
                //do nothing
            }
        }
        return null;
    }

    public static Map<String, List<String>> getBodyContentWithClientId(String clientId) {

        Map<String, String> content = new HashMap<>();
        if (StringUtils.isNotEmpty(clientId)) {
            content.put(OAuth.OAUTH_CLIENT_ID, clientId);
        }

        Map<String, List<String>> bodyContent = new HashMap<>();
        content.forEach((key, value) -> {
            List<String> valueList = new ArrayList<String>();
            valueList.add(value);
            bodyContent.put(key, valueList);
        });
        return bodyContent;
    }

    @Test(dataProvider = "testAuthenticateClientWhenJWKSEndPointGiven")
    public void testAuthenticateClientWhenJWKSEndPointGiven(Object certificate, HashMap<String, List> bodyContent,
            Object oAuthClientAuthnContextObj, boolean authenticationResult, String TEST_JSON)
            throws Exception {

        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.mockStatic(MutualTLSUtil.class);
        OAuthClientAuthnContext oAuthClientAuthnContext = (OAuthClientAuthnContext) oAuthClientAuthnContextObj;
        HttpServletRequest httpServletRequest = PowerMockito.mock(HttpServletRequest.class);

        PowerMockito.when(OAuth2Util.getTenantDomainOfOauthApp(Matchers.anyString())).thenReturn("carbon.super");
        PowerMockito.when(OAuth2Util.getX509CertOfOAuthApp(oAuthClientAuthnContext.getClientId(), "carbon.super"))
                .thenReturn(null);
        PowerMockito.when(MutualTLSUtil.getJWKSEndpoint(any()))
                .thenReturn(new URL("https://buddhima.auth0.com/.well-known/jwks.json"));
        PowerMockito.when(MutualTLSUtil.getResourceContent(any())).thenReturn(TEST_JSON);
        PowerMockito.when(MutualTLSUtil.getJsonArray(any())).thenReturn(getJsonArray(TEST_JSON));
        PowerMockito.when(MutualTLSUtil.getThumbPrint(any())).thenReturn("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        PowerMockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn(certificate);
        assertEquals(mutualTLSClientAuthenticator
                        .authenticateClient(httpServletRequest, bodyContent, oAuthClientAuthnContext), authenticationResult,
                "Expected client authentication result was not " + "received");
    }

    public static JsonArray getJsonArray(String resource) {

        JsonParser jp = new JsonParser();
        InputStream inputStream = new ByteArrayInputStream(resource.getBytes(Charset.forName("UTF-8")));
        JsonElement root = jp.parse(new InputStreamReader(inputStream));
        JsonObject rootobj = root.getAsJsonObject();
        return rootobj.get("keys").getAsJsonArray();
    }
}
