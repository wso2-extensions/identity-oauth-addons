package org.wso2.carbon.identity.dpop;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS384;

public class TestUtils {

    private static final String rsaPublicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt9x8A/JZb313HsuwnUNMat52cNQSo"+
            "I7HfHtv2IwM7QFtuq/HzMLwlYajYPIkaCiIhG67vGStNQAYPUG+z7fW6uXI3cLX+9ws2moPwj"+
            "SnPhCf/UFmwRUXSSXNBUthVWTFJeUIYQ/WldeZyOD4LGpc+OhxHkj4PQvz2nZUhYM0vu163a8"+
            "NbKvC3IQ+pbFOmW9mnGCSO2YqPN/zS1G1X76CdGxtJzVIpdjj4/HgoKCo+RAysMnnKDQz3+lm"+
            "d+kQBqXzvVx0ZNuPY/B7nBzT6kvKqNBRwduPwzEgkH3rBpIBv0Ve+pHdI6Tm/2c6bC1NRlu+b"+
            "/g8CeZDE0tZ4IyhTVsAIQIDAQAB";

    private static final String rsaPrivateKey =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC33HwD8llvfXcey7CdQ0xq3"+
            "nZw1BKgjsd8e2/YjAztAW26r8fMwvCVhqNg8iRoKIiEbru8ZK01ABg9Qb7Pt9bq5cjdwtf73C"+
            "zaag/CNKc+EJ/9QWbBFRdJJc0FS2FVZMUl5QhhD9aV15nI4Pgsalz46HEeSPg9C/PadlSFgzS"+
            "+7Xrdrw1sq8LchD6lsU6Zb2acYJI7Zio83/NLUbVfvoJ0bG0nNUil2OPj8eCgoKj5EDKwyeco"+
            "NDPf6WZ36RAGpfO9XHRk249j8HucHNPqS8qo0FHB24/DMSCQfesGkgG/RV76kd0jpOb/ZzpsL"+
            "U1GW75v+DwJ5kMTS1ngjKFNWwAhAgMBAAECggEADrgFa5F2rHC4XQxEZsqQ7wtBIxYvKZBUkv"+
            "gUw5qunDidjrDsx00h0m6VXLj1xirchvGQcOwEW7ZWumyteFaIy4Q6uNoUzVJaet+7xDnP262"+
            "cCTu3nKRyGUZ/67kVoS7wg3Ca455PeO5qHsU3yOJ47+o3yAtiaAyxaF9Js+iFi/U3JCM54S9s"+
            "OiTP7j62O72CZhqZcQcmZcbxXzJl/4F9pIJvMaj5IAWt7KNZGlZ62aa1G+cXWghcCcgQf7k7I"+
            "eWAPbHl1eviXDxGo9mIG41NMCklZOpdmQkTStsEVzALI+jx9miqv1Beenb+hHoK7oiKTFCl9f"+
            "vB1yFunJl1zHEWeQKBgQDIODvXMz34i74kzVZzyUkBve10J2xjTqSTB0XZVUEJeWmsWWLUbvy"+
            "xmeLrVOMMPwLQi5JmloAcUdfXSUkU73fOGDJ8K1Z0Tm8NHIl2UBgWmZfIpg/rZDqb195cqWZz"+
            "/nf1Nko8WJXFGwBmeLPR4HVvIa7HeSglUjCGY0QKBefiLQKBgQDrFY/N9HezKMjtaj5JYjRLL"+
            "FNf3wE/CqmYa9+w6U96AVNswD/DlCPnCGRo7fpmobm2brEDKVJm78ZBfMIL3p76O6OjFlQT+o"+
            "P/2dAE6hU4MlYmr+w2Mqxut+BSNv6AHgtdKRUxAY6Ld5EocKdabwaL9t/TiY8pAcS9rT63DI9"+
            "yRQKBgQC+S/xMOG7RGXian/NoT0qtdigHOyUgafGvsLzpqMcMyzHt1nNBd0+DOcDcbSzzSbxS"+
            "HCYEjUysHfmorAXi+QuEfakWLVaZaqbP7myUX+HVMRx7X6JH11aBIrY8meE/o/+9t2DtZEDNO"+
            "zGxM02tz8mt23S0MGpAtpJaWGSlpiFT7QKBgDoEUj8z7C6tDBl7tO+Lavh6cgEhGj+itARH6y"+
            "bQDatAlIQsVhBAiTPFYHJ8+OVHWHvriYgMNKfu2PDkh0dCo92BxnrDUfC0TMthx/LOinoaAiT"+
            "+Gb+uddvFSXlA1UJtJ8TQFMjJZ5KH6a0fUE4DRIxaWxbrxgcKxrFBBk9KrEQ5AoGBAKcFnoup"+
            "LWTebgLlQ2ox80sXTdCdweSdHv8tIAZGZUs97BcPpTujyVldx7bRgLpcV93FpBafPIN5FjU1H"+
            "uihfak3h0SQi2WxyCJpZiH+XNK/9tabN2MKQji7wjbrQRN06jNuUXeo6X18vcBVVVj2TogFJL"+
            "fQqNUgIMZN35pyBtja";

    private static final String ecPublicKey =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+6F4irv76jwSiLHebVzksLfjtXYplS9RwmvJF"+
            "dRp+rcZtUIbQLcscH1SjsIigl4Ha80CG14Y0OofBVwwS7IAjQ==";

    public static final String ecPrivateKey =
            "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAfBD6WwWEgj5FQ01/2zqR4NNu/i"+
            "MEB/6fwhaMMh3GQFw==";

    public static final String jwtAccessToken =
            "eyJ4NXQiOiJyVDVGYi1Cd1doWUZYWE9JQjlnaG9NZDhfSWsiL"+
            "CJraWQiOiJPV1JpTXpaaVlURXhZVEl4WkdGa05UVTJOVE0zTW"+
            "pkaFltTmxNVFZrTnpRMU56a3paVGc1TVRrNE0yWmxOMkZoWkd"+
            "aalpURmlNemxsTTJJM1l6ZzJNZ19SUzI1NiIsInR5cCI6ImF0"+
            "K2p3dCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI5MTAwMjEwZ"+
            "C1mOWRlLTQyMGYtYmQzMy0wZDJlNDdhMzBmMWEiLCJhdXQiOi"+
            "JBUFBMSUNBVElPTl9VU0VSIiwiYmluZGluZ190eXBlIjoiRFB"+
            "vUCIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wv"+
            "b2F1dGgyXC90b2tlbiIsImNsaWVudF9pZCI6InFNeFZKcXFRZ"+
            "GUzYTJQQTR2ZjdYUFJ0dHVRZ2EiLCJhdWQiOiJxTXhWSnFxUW"+
            "RlM2EyUEE0dmY3WFBSdHR1UWdhIiwibmJmIjoxNzEzMTY2ODk"+
            "0LCJhenAiOiJxTXhWSnFxUWRlM2EyUEE0dmY3WFBSdHR1UWdh"+
            "Iiwib3JnX2lkIjoiMTAwODRhOGQtMTEzZi00MjExLWEwZDUtZ"+
            "WZlMzZiMDgyMjExIiwic2NvcGUiOiJvcGVuaWQiLCJjbmYiOn"+
            "siamt0IjoiUERmaEM3Tmd5LXRjTU1qNUtaLVI1QU9ESnJySTJ"+
            "5NmNOTXVPRE81VWlLQSJ9LCJleHAiOjE3MTMxNzA0OTQsIm9y"+
            "Z19uYW1lIjoiU3VwZXIiLCJpYXQiOjE3MTMxNjY4OTQsImJpb"+
            "mRpbmdfcmVmIjoiNzcwNGFkNmRlMThjZDFmNmRjZjBiNDI4Yz"+
            "c0MjNlNTQiLCJqdGkiOiJkNTAyMTZjOC04OWE1LTQ0OGItODY"+
            "wOC1lZmMwY2E2MmM3YjkifQ.eFLih6yMjruvded38eGb9Sopr"+
            "_a3lJKKLIalZkp2QTChZTtba67Gue_yZ2OkK-0KiTsFx9MU0w"+
            "i1dVzEr-2UQSj6Mt7pyp5y_bQp4kP2OY7RgNgMIXTDnHh6PQ4"+
            "Ve5W0UmcNFso4Uc3uQPvbQuLoYomTxDqnWebXMbWFqdu1Df_g"+
            "IbaYJEjaDPkj91x-86ajU41wDKb1S4sGzh4HE_f5akMWVb5D0"+
            "p6szJ-9ieM-HEYcv0zs-0OiwgVPxdpT_uIy2GL9ca6eIeHSBI"+
            "me_l_8fqNnkYB0LQD9hIzvdNDOpQhKallPucchkjUF3tXXEnF"+
            "QPe6xT-Qc1y-OhTWk-ActXw";

    public static final String accessTokenHash = "AGYGxGwNMSqZMpwTtCJsKPP42Q8paPyfMWshrnoZFe0";

    public static final String EC_DPOP_JWK_THUMBPRINT = "C07a9MZgz5wYywPc39Tw81gE8QzhkpC14sjx-2pAwbI";

    public static final String RSA_DPOP_JWK_THUMBPRINT = "_Z3DHS03lCZVeRs-J9fO7JHuTE0BmVYuBF6Rdc5qjII";

    public static String genarateDPoPProof(String keyPairType, String jti, String httpMethod, String httpUrl, Date iat, boolean includeAccessTokenHash)
            throws NoSuchAlgorithmException, JOSEException, IOException, InvalidKeySpecException {

        /* Read all bytes from the private key file */
        String privateKeyString = keyPairType.equals("RSA") ? rsaPrivateKey : ecPrivateKey;
        byte[] bytes = Base64.getDecoder().decode(privateKeyString);

        /* Generate private key. */
        PKCS8EncodedKeySpec privateKs = new PKCS8EncodedKeySpec(bytes);
        KeyFactory privateKf = KeyFactory.getInstance(keyPairType);
        PrivateKey privateKey = privateKf.generatePrivate(privateKs);

        /* Read all the public key bytes */
        String publicKeyString = keyPairType.equals("RSA") ? rsaPublicKey : ecPublicKey;
        byte[] pubBytes = Base64.getDecoder().decode(publicKeyString);

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(pubBytes);
        KeyFactory kf = KeyFactory.getInstance(keyPairType);
        PublicKey publicCert = kf.generatePublic(ks);

        JWK jwk;
        if ("EC".equals(keyPairType)) {
            jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicCert).build();
        }
        else {
            jwk = new RSAKey.Builder((RSAPublicKey) publicCert).build();

        }

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.issueTime(iat);
        jwtClaimsSetBuilder.jwtID(jti);
        jwtClaimsSetBuilder.claim("htm", httpMethod);
        jwtClaimsSetBuilder.claim("htu", httpUrl);
        if (includeAccessTokenHash) {
            jwtClaimsSetBuilder.claim("ath", accessTokenHash);
        }

        JWSHeader.Builder headerBuilder;
        if ("EC".equals(keyPairType)) {
            headerBuilder = new JWSHeader.Builder(ES256);
        } else {
            headerBuilder = new JWSHeader.Builder(RS384);
        }
        headerBuilder.type(new JOSEObjectType("dpop+jwt"));
        headerBuilder.jwk(jwk);
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), jwtClaimsSetBuilder.build());

        if ("EC".equals(keyPairType)) {
            ECDSASigner ecdsaSigner = new ECDSASigner(privateKey, Curve.P_256);
            signedJWT.sign(ecdsaSigner);
        } else {
            RSASSASigner rsassaSigner = new RSASSASigner(privateKey);
            signedJWT.sign(rsassaSigner);
        }
        return signedJWT.serialize();
    }
}
