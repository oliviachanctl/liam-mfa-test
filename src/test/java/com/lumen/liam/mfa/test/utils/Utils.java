package com.lumen.liam.mfa.test.utils;

import java.security.SignatureException;
import java.util.Date;
import java.security.MessageDigest.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static io.restassured.RestAssured.given;

public class Utils {

    public static String calculateRFC2104HMAC(String epochTime, String appKeySecret)
            throws java.security.SignatureException {
        String result;

        try {
            // get an sha256 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(appKeySecret.getBytes(),"HmacSHA256");

            // get an sha256 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(epochTime.getBytes());

            // base64-encode the hmac
            result = new String(Base64.encode(rawHmac));

        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC : "
                    + e.getMessage());
        }
        return result;
    }


    public static HttpHeaders setDigestHttpHeader (String secret, String digestTime){
        try {

            String digest = calculateRFC2104HMAC(digestTime, secret);
            HttpHeaders userHttpHeaders = new HttpHeaders();;
            userHttpHeaders.add("x-application-key", System.getProperty("liamapi.header.apiKey"));
            userHttpHeaders.add("x-digest", digest);
            userHttpHeaders.add("x-digest-Time", digestTime);
            return userHttpHeaders;
        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }

    public static HttpHeaders setUserHttpHeader (String secret, String digestTime){
        try {

            String digest = calculateRFC2104HMAC(digestTime, secret);
            HttpHeaders userHttpHeaders = new HttpHeaders();
            userHttpHeaders.add("Accept", "application/json");
            userHttpHeaders.add("content-type", "application/json");
            userHttpHeaders.add("x-application-key", System.getProperty("liamapi.header.apiKey"));
            userHttpHeaders.add("x-digest", digest);
            userHttpHeaders.add("x-digest-Time", digestTime);
            return userHttpHeaders;
        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }

    public static HttpHeaders setMfaHttpHeader (String secret, String digestTime, String token){
        try {

            String digest = calculateRFC2104HMAC(digestTime, secret);
            HttpHeaders mfaHttpHeaders = new HttpHeaders();
            mfaHttpHeaders.add("Authorization", "Bearer " + token);
            mfaHttpHeaders.add("Accept", "application/json");
            mfaHttpHeaders.add("x-liam-env", System.getProperty("liamapi.header.x-liam-env"));
            mfaHttpHeaders.add("content-type", "application/json");
            mfaHttpHeaders.add("x-application-key", System.getProperty("liamapi.header.apiKey"));
            mfaHttpHeaders.add("x-digest", digest);
            mfaHttpHeaders.add("x-digest-time", digestTime);
            return mfaHttpHeaders;
        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }


    public static String getGraphToken() {

        Response response =
                given().contentType("application/x-www-form-urlencoded")
                        .urlEncodingEnabled(true)
                        .formParam("grant_type", "client_credentials")
                        .formParam("client_id", System.getProperty("azureb2c.human.clientid"))
                        .formParam("client_secret", System.getProperty("azureb2c.human.secret"))
                        .formParam("scope", "https://graph.microsoft.com/.default")
                        .when()
                        .post("https://login.microsoftonline.com/"+ System.getProperty("azureb2c.tenantid")+"/oauth2/v2.0/token");


        JsonPath jsonPathEvaluator = response.jsonPath();

        return jsonPathEvaluator.getString("access_token");

    }

}
