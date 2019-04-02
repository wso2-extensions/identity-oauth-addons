
/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth2.token.handler.clientauth.mutualtls.utils;

import com.google.gson.JsonArray;
import org.apache.commons.lang.StringUtils;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.xml.bind.DatatypeConverter;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

import static org.testng.Assert.*;

/**
 * Test class for MutualTLSUtil class.
 */
@WithCarbonHome
@PrepareForTest(OAuth2Util.class)
public class MutualTLSUtilTest extends PowerMockTestCase {

    @Test
    public void testGetPropertyValue() {
        ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
        serviceProviderProperty.setName("a");
        serviceProviderProperty.setValue("b");
        ServiceProviderProperty[] serviceProviderProperties = new ServiceProviderProperty[1];
        serviceProviderProperties[0] = serviceProviderProperty;
        assertEquals(MutualTLSUtil.getPropertyValue(serviceProviderProperties, "a"), "b");
    }

    @Test
    public void testGetJsonArray() {

        String testJson = "{\n" + "  \"keys\" : [ {\n" + "    \"e\" : \"AQAB\",\n"
                + "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" + "    \"kty\" : \"RSA\",\n"
                + "    \"n\" : \"x_AfraZx04boy3Xti7oPXMEi16ZiXWIiFy6ciFHjFZBDLEpUHJV5UaGIVl60iEHUAupKqq4hnjE4APFj1pLr"
                + "s55QGDoTgSuTRw2xIzMSVjcUREM-UZFBlOXduL2B1SiYQdT8ctprJRZPvOkYZyUoYLPg9n1pEp_CVYeYhV71gLUmCmrUe52LP-T"
                + "ERvjk7gF16c8UCVT7G4xtzWw1hJtc1eDB5v6NsxpWRr5j2F6VdRvN__wuRRglmN1Gdw039ZvEGdCt-SEnVn4dpVuQ\",\n"
                + "    \"use\" : \"tls\",\n"
                + "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUTI5MjNCQ0YyMkM2MkU1MQ.pem\",\n"
                + "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" + "  }, {\n" + "    \"e\" : \"AQAB\",\n"
                + "    \"kid\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\",\n" + "    \"kty\" : \"RSA\",\n"
                + "    \"n\" : \"PO5ED5fWt8_-g1hFttbORNAH9dJF0fbwdeJclG3rKuJDzLF80rIV88cFY1Iug_kRerjlSD5yQ5bJfNeP-V7XKI"
                + "Lo570RR7GThgLwmWNWAWK6dPQ57euwhMS8TWpuo27CHUirKAoBzPywcssPcpfRaT0dNv_83AkxRtsOUMizAWVh8MGhUUe2bHpQdR"
                + "xKD_0X7U_5V3Y0aPFUikICTW2_Je8jbQ\",\n" + "    \"use\" : \"sig\",\n"
                + "    \"x5u\" : \"https://keystore.abc.org.lk/RjM3REY1MEVFMUQ2TZDNzIyMjNCQ0YyMkM2MkU1MQ.pem\",\n"
                + "    \"x5t#S256\" : \"dn/viC56rPBozVX4DxPaHIzxocfK\"\n" + "  } ]\n" + "}";
        JsonArray jsonArray = MutualTLSUtil.getJsonArray(testJson);
        assertTrue(StringUtils.isNotBlank(jsonArray.get(0).toString()));
    }

    @Test
    public void testGetThumbPrint() throws Exception {

        String CERTIFICATE_CONTENT = "MIIDmzCCAoOgAwIBAgIJAJuzH6NrV5s5MA0GCSqGSIb3DQEBCwUAMGQxCzAJBgNV"
                + "BAYTAlNMMQswCQYDVQQIDAJXUDEQMA4GA1UEBwwHQ29sb21ibzENMAsGA1UECgwE\n"
                + "d3NvMjENMAsGA1UECwwEd3NvMjEYMBYGA1UEAwwPdHJhdmVsb2NpdHkuY29tMB4X\n"
                + "DTE4MDIwNjEwNTk1N1oXDTE5MDIwNjEwNTk1N1owZDELMAkGA1UEBhMCU0wxCzAJ\n"
                + "BgNVBAgMAldQMRAwDgYDVQQHDAdDb2xvbWJvMQ0wCwYDVQQKDAR3c28yMQ0wCwYD\n"
                + "VQQLDAR3c28yMRgwFgYDVQQDDA90cmF2ZWxvY2l0eS5jb20wggEiMA0GCSqGSIb3\n"
                + "DQEBAQUAA4IBDwAwggEKAoIBAQDlKn3dmaLW7iBOKdlWY8Go8Q7kR6HNY/8j0arv\n"
                + "EcZYqMrihcSX5i5Mz57t6Z3xpaGay2jPWND7dDA/RocircleBKQk0X2OxoEYba3W\n"
                + "t477EpN9RWGAZuuANUSVKjC8FsNYhEp9y59IuxK+IgDAEfR8O2RNLYA6O3UjBC/R\n"
                + "f443CwOE4jFm3eVAeLIBudn/viC56rPBozVX4DxPaHIzxocfK6EpDljEG4lJ7otS\n"
                + "SbIpPlmAO/0f8F1Q6syv+sCkPRGn/OjTXWtUg6QXAclguOCl3MI+pLMThQUATcKb\n"
                + "2QkPl8r8/b/S8qMRKzSVYyjNP+CsDRO/MdlC50QZSJBaNYqdAgMBAAGjUDBOMB0G\n"
                + "A1UdDgQWBBSIXyhWV6Ac+FiqdXEeQwqzJfFLhDAfBgNVHSMEGDAWgBSIXyhWV6Ac\n"
                + "+FiqdXEeQwqzJfFLhDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBQ\n"
                + "S2jmfzF8x1iwmRqXILZ6qkF5ABAlNa3Z3bMFB7uErw2BxASMOLWfjZdEcyICDGIf\n"
                + "ZeYchqEPTvv/RIqDlu8xda3N2kRp1un5Hfffavm6ZWR3J8LdsnSjrehZ/afxuy8a\n"
                + "OFKiRtj9tqpG3C/s/NBJ9Gl4u5YhihOSJG9ELihJSxWDYI641AOalWnUQ/SxfeCO\n"
                + "TY75aViCAD6QDmBxe/opQYExBdgNOCQ6HdP5WWBT6EEggBe/mqOM/dchj57rpPtw\n"
                + "IOQjy9UCaY7tq4SmhAJyab0mxjcFoRBpzOJIDh+N8ozSDK+MepyFSwtW5zVacOiG\n" + "OQUrBTGXQFZOGKje8sbS";

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate Cert = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(CERTIFICATE_CONTENT)));
        assertEquals(MutualTLSUtil.getThumbPrint(Cert), "OTE2OWI4MzQ0MTQ5ZDMzMTk3ZmI2NjNjOGYyNjZhNTZhYzgxZWU5Zg");

    }

    @Test
    public void testIsJwksUriConfigured() throws Exception {

        String clientID = "someClientID";
        ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProviderProperty.setName("jwksURI");
        serviceProviderProperty.setValue("someJWKSURI");
        ServiceProviderProperty[] serviceProviderProperties = new ServiceProviderProperty[1];
        serviceProviderProperties[0] = serviceProviderProperty;
        serviceProvider.setSpProperties(serviceProviderProperties);
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.when(OAuth2Util.getServiceProvider(clientID, SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(serviceProvider);
        assertTrue(MutualTLSUtil.isJwksUriConfigured(clientID, SUPER_TENANT_DOMAIN_NAME));
    }
}