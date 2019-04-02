
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
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;

import static org.testng.Assert.*;

public class MutualTLSUtilTest {

    @Test
    public void testGetPropertyValue() {
        ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
        serviceProviderProperty.setName("a");
        serviceProviderProperty.setValue("b");
        ServiceProviderProperty [] serviceProviderProperties =  new ServiceProviderProperty[1];
        serviceProviderProperties[0]= serviceProviderProperty;
        assertEquals(MutualTLSUtil.getPropertyValue(serviceProviderProperties,"a"),"b");
    }

    @Test
    public void testGetJsonArray() {

         String TEST_JSON = "{\n" +
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
        JsonArray jsonArray = MutualTLSUtil.getJsonArray(TEST_JSON);
        assertEquals(StringUtils.isNotBlank(jsonArray.get(0).toString()),true);
    }
}