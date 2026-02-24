/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.token.handler.clientauth.tlswithidsecret.util.MutualTLSUtil.JAVAX_SERVLET_REQUEST_CERTIFICATE;

@WithCarbonHome
public class MutualTLSWithIdSecretAuthenticatorTest {

    private static String CLIENT_ID = "someclientid";
    private static String CLIENT_SECRET = "someclientsecret";
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

    private MutualTLSWithIdSecretAuthenticator mutualTLSWithIdSecretAuthenticator =
            new MutualTLSWithIdSecretAuthenticator();

    public static Map<String, List<String>> getBodyContentWithClientCredentials(String clientId, String clientSecret) {

        Map<String, String> content = new HashMap<>();
        if (StringUtils.isNotEmpty(clientId)) {
            content.put(OAuth.OAUTH_CLIENT_ID, clientId);
        }
        if (StringUtils.isNotEmpty(clientSecret)) {
            content.put(OAuth.OAUTH_CLIENT_SECRET, clientSecret);
        }
        Map<String, List<String>> bodyContent = new HashMap<>();
        content.forEach((key, value) -> {
            List<String> valueList = new ArrayList<String>();
            valueList.add(value);
            bodyContent.put(key, valueList);
        });
        return bodyContent;
    }

    public void testAuthenticateClient() {

    }

    @DataProvider(name = "testCanAuthenticateData")
    public Object[][] testCanAuthenticateData() {

        return new Object[][]{

                {getCertificate(CERTIFICATE_CONTENT), new HashMap<String, List>(), false},
                {getCertificate(CERTIFICATE_CONTENT), getBodyContentWithClientCredentials(CLIENT_ID, CLIENT_SECRET),
                        true},
                {getCertificate(CERTIFICATE_CONTENT), getBodyContentWithClientCredentials(CLIENT_ID, null), false},
        };
    }

    @Test(dataProvider = "testCanAuthenticateData")
    public void testCanAuthenticate(X509Certificate certificate, HashMap<String, List> bodyContent, boolean canHandle) {

        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE)).thenReturn(certificate);
        assertEquals(mutualTLSWithIdSecretAuthenticator.canAuthenticate(httpServletRequest, bodyContent, new
                OAuthClientAuthnContext()), canHandle, "Expected can authenticate evaluation not received");
    }

    @DataProvider(name = "testIsEnabledData")
    public Object[][] testIsEnabledData() {

        return new Object[][]{

                {"true"},
                {"false"}
        };
    }

    @Test(dataProvider = "testIsEnabledData")
    public void testIsEnabled(String isEnabled) {

        IdentityEventListenerConfig identityEventListenerConfig = Mockito.mock(IdentityEventListenerConfig.class);
        try (MockedStatic<IdentityUtil> identityUtilMockedStatic = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMockedStatic.when(() -> IdentityUtil.readEventListenerProperty(
                    AbstractIdentityHandler.class.getName(), MutualTLSWithIdSecretAuthenticator.class.getName()))
                    .thenReturn(identityEventListenerConfig);
            Mockito.when(identityEventListenerConfig.getEnable()).thenReturn(isEnabled);
            assertEquals(mutualTLSWithIdSecretAuthenticator.isEnabled(), Boolean.parseBoolean(isEnabled));
        }
    }

    @Test
    public void testGetPriority() {

        assertEquals(101, mutualTLSWithIdSecretAuthenticator.getPriority(), "Mutual " +
                "TLS client with ID Secret authenticator priority has changed.");
    }

    @Test
    public void testGetName() {

        assertEquals("MutualTLSWithIdSecretAuthenticator", mutualTLSWithIdSecretAuthenticator.getName(), "Mutual " +
                "TLS client with ID Secret authenticator name has changed.");
    }

    private X509Certificate getCertificate(String certificateContent) {

        if (StringUtils.isNotBlank(certificateContent)) {
            // Build the Certificate object from cert content.
            try {
                return (X509Certificate) IdentityUtil.convertPEMEncodedContentToCertificate(certificateContent);
            } catch (CertificateException e) {
                // Do nothing.
            }
        }
        return null;
    }

    private OAuthClientAuthnContext buildOAuthClientAuthnContext(String clientId) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setClientId(clientId);
        return oAuthClientAuthnContext;
    }
}