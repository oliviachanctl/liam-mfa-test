package com.lumen.liam.mfa.test.utils;

import io.restassured.response.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import static io.restassured.RestAssured.given;


public class UtilsMFA {

    //TODO:  check liam database for audit log (Jammy and Santhosh)

    private static final Logger logger = LogManager.getLogger(UtilsMFA.class);
    private static HttpHeaders mfaHttpHeaders = new HttpHeaders();
    private static String mfaEnabledExtention = "extension_" + System.getProperty("azureb2c.human.extensionid") + "_mfaEnabled";
    private static String mfaTypeExtention = "extension_" + System.getProperty("azureb2c.human.extensionid") + "_mfaType";

    //Return the liamId of a user
    public Response ResetMFA(String liamId, String userName, String mfaType, int expectedCode, String expectedStatus, String expectedMessage) {

        return given()
                .headers(mfaHttpHeaders)
                .and()
                .body(buildResetRequest(liamId, userName))
                .when()
                .put("/reset")
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value())
                .extract().response();
    }

    public static boolean verifyMFAInB2C(String endpoint, String token, String uid, Boolean expectedMfaState, String expectedMfaType) {

        Boolean mfaState = !expectedMfaState;

        long endTime = System.currentTimeMillis() + 30000;          //wait up to 30sec

        while (null != mfaState && !expectedMfaState == mfaState && System.currentTimeMillis() < endTime) {
            wait(1000);
            Response response = given().header("Authorization", "Bearer " + token)
                    .get(endpoint + uid + "?$select=" + mfaEnabledExtention + "," + mfaTypeExtention)
                    .then()
                    .statusCode(200)
                    .extract().response();

            //if (response.getBody().asPrettyString().contains(mfaEnabledExtention)){
            if (response.asPrettyString().contains(mfaEnabledExtention)){

                mfaState = response.path("\n" + mfaEnabledExtention + "\n" );
            }
            logger.info("response = " + response.asPrettyString());
            logger.info("mfaState = " + mfaState);
        }
        return expectedMfaState == mfaState;
    }

    public static boolean verifyMFAResetInB2C(String endpoint, String token, String uid) {


        long endTime = System.currentTimeMillis() + 30000;          //wait up to 30sec
        boolean hasMfa = true;
        while (System.currentTimeMillis() < endTime && hasMfa) {
            wait(1000);
            Response response =  given().header("Authorization", "Bearer " + token)
                    .get(endpoint + uid + "?$select=" + mfaEnabledExtention + "," + mfaTypeExtention)
                    .then()
                    .statusCode(200)
                    .extract().response();
            logger.info("Response = " + response.asPrettyString());
            hasMfa = response.asPrettyString().contains("mfa");
        }
        return !hasMfa;

    }

    public static String buildRequest(String liamId, String userName, String mfaType){
        return "{" +
                "\"liamId\": \""+ liamId +"\" ," +
                "\"mfaType\": \""+ mfaType +"\"," +
                "\"username\": \""+ userName +"\"" +
                "}";

    }

    public static String buildResetRequest(String liamId, String userName){
        return "{" +
                "\"liamId\": \""+ liamId +"\" ," +
                "\"username\": \""+ userName +"\"" +
                "}";

    }

    private static void wait(int ms)
    {
        try
        {
            Thread.sleep(ms);
        }
        catch(InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }
    }
}

