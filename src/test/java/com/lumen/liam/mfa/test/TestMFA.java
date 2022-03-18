package com.lumen.liam.mfa.test;

import com.lumen.liam.mfa.test.utils.Utils;
import com.lumen.liam.mfa.test.utils.UtilsMFA;
import com.lumen.liam.mfa.test.utils.UtilsUser;
import io.restassured.RestAssured;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.Properties;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


//@TestWithResources

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TestMFA {

    //TODO:  check liam database for audit log (Jammy and Santhosh)

    private static final Logger logger = LogManager.getLogger(TestMFA.class);
    private static final String liamMfaEndpoint =System.getProperty("server.endpoint.liammfa");
    private static final String liamUserEndpoint = System.getProperty("server.endpoint.users");  //System.getProperty("server.url") + System.getProperty("server.endpoint.users");
    private static final String graphEndpoint = System.getProperty("azureb2c.graph.endpoint");
    private static HttpHeaders mfaHttpHeaders = new HttpHeaders();
    private static HttpHeaders userHttpHeaders = new HttpHeaders();
    private static HttpHeaders digestHttpHeaders = new HttpHeaders();
    private static Properties prop = new Properties();
    private  String token, propertiesFile, liamId, userName, mfaType = null;

    @BeforeAll
    public void setup()  {
        propertiesFile = "TestMFA.properties";

        try (InputStream input = TestMFA.class.getClassLoader().getResourceAsStream(propertiesFile)) {
            if (input == null) {
                logger.info("Sorry, unable to find " + propertiesFile);
                return;
            }
            // load a properties file
            prop.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //userName =prop.getProperty("username");
        //mfaType = prop.getProperty("mfaType");

        //RestAssured settings
        RestAssured.baseURI = System.getProperty("server.url") + liamMfaEndpoint;
        RestAssured.useRelaxedHTTPSValidation();
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();

       
        //get B2C token
        if (token == null) {
            token = Utils.getGraphToken();
            logger.info("token is " + token);
        }

        //set liam headers
        String digestTime = new Date().getTime() + "";
        String secret= System.getProperty("apigee.human.secret");
        digestHttpHeaders = Utils.setDigestHttpHeader(secret,digestTime);
        userHttpHeaders = Utils.setUserHttpHeader(secret,digestTime);
        mfaHttpHeaders = Utils.setMfaHttpHeader(secret,digestTime, token);


    }





    @ParameterizedTest
    @CsvFileSource(resources = "/testdata/testEnableMFA.csv", numLinesToSkip = 1)
    @Order(1)
    void testEnableMFA(String userName, String mfaType) {
        liamId = prepTestUser(liamUserEndpoint, mfaHttpHeaders, userName );
        disableMFA(liamId,userName);
        given()
                .headers(mfaHttpHeaders)
                .contentType("application/json")
                .and()
                .body(UtilsMFA.buildRequest(liamId, userName, mfaType))
                .when()
                .put("/enable")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());

        //TODO: check response details when available

        //check B2C user with Graph API
        Assertions.assertTrue(UtilsMFA.verifyMFAInB2C(graphEndpoint,  token, liamId, true, mfaType));
    };

    @ParameterizedTest
    @CsvFileSource(resources = "/testdata/testEnableMFA_ErrorCodes.csv", numLinesToSkip = 1,delimiter='|')
    @Order(2)
    void testEnableMFA_ErrorCodes(String liamId, String userName, String mfaType, int expectedCode, String expectedStatus, String expectedMessage) {
        if (liamId == null){
            liamId = prepTestUser(liamUserEndpoint, mfaHttpHeaders, userName );
        }
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildRequest(liamId, userName, mfaType))
                .when()
                .put("/enable")
                .then()
                .assertThat()
                .statusCode(expectedCode)
                .body("code", equalTo(expectedCode))
                .body("status", equalTo(expectedStatus))
                .body("message", equalTo(expectedMessage));
    }

    @Test
    void testEnableMFAExpiredToken() {
        //given().headers(digestHttpHeaders)
        given()
                .header("Authorization","Bearer " + prop.getProperty("expiredJwtToken"))
                .header("x-liam-env",System.getProperty("liamapi.header.x-liam-env"))
                .header("content-type","application/json")
                .and()
                .body(UtilsMFA.buildRequest(prop.getProperty("liamId"), prop.getProperty("username"), prop.getProperty("mfaType")))
                .when()
                .put("/enable")
                .then()
                .assertThat()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .body("code", equalTo(HttpStatus.UNAUTHORIZED.value()))
                .body("status", containsStringIgnoringCase(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                .body("message", containsString(prop.getProperty("expiredTokenMessage")));
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/testdata/testEnableMFAIntServerError.csv", numLinesToSkip = 1)
    void testEnableMFAIntServerError( String body) {

        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(body)
                .when()
                .put("/enable")
                .then()
                .assertThat()
                .body("path", containsStringIgnoringCase(System.getProperty("server.endpoint.liammfa")+"/enable"))
                .body("status", equalTo(HttpStatus.INTERNAL_SERVER_ERROR.value()))
                .body("error", equalTo(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/testdata/testDisableMFA.csv", numLinesToSkip = 1)
    @Order(3)
    void testDisableMFA(String userName, String mfaType) {
        liamId = prepTestUser(liamUserEndpoint, mfaHttpHeaders, userName );
        enableMFA(liamId,userName,mfaType);
        given()
                .headers(mfaHttpHeaders)
                .contentType("application/json")
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/disable")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());
        Assertions.assertTrue(UtilsMFA.verifyMFAInB2C(graphEndpoint,token, liamId, false, mfaType));
    }

    @ParameterizedTest()
    @CsvFileSource(resources = "/testdata/testDisableMFA_ErrorCodes.csv", numLinesToSkip = 1,delimiter='|')
    @Order(4)
    void testDisableMFA_ErrorCodes(String liamId, String userName, int expectedCode, String expectedStatus, String expectedMessage) {
        if (liamId == null){
            liamId = prepTestUser(liamUserEndpoint, mfaHttpHeaders, userName );
        }
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/disable")
                .then()
                .assertThat()
                .statusCode(expectedCode)
                .body("code", equalTo(expectedCode))
                .body("status", equalTo(expectedStatus))
                .body("message", equalTo(expectedMessage));;
    }


    @Test
    void testDisableMFAExpiredToken() {
        given()
                .headers(mfaHttpHeaders)
                .header("Authorization","Bearer " + prop.getProperty("expiredJwtToken"))
//                .header("x-liam-env",System.getProperty("liamapi.header.x-liam-env"))
//                .header("content-type","application/json")
                .and()
                .body(UtilsMFA.buildRequest(prop.getProperty("liamId"), prop.getProperty("username"), prop.getProperty("mfaType")))
                .when()
                .put("/disable")
                .then()
                .assertThat()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .body("code", equalTo(HttpStatus.UNAUTHORIZED.value()))
                .body("status", containsStringIgnoringCase(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                .body("message", containsString(prop.getProperty("expiredTokenMessage")));
    }


    @ParameterizedTest
    @CsvFileSource(resources = "/testdata/testResetMFA.csv", numLinesToSkip = 1)
    @Order(5)
    void testResetMFA(String userName, String mfaType) {
        liamId = prepTestUser(liamUserEndpoint, mfaHttpHeaders, userName );
        enableMFA(liamId, userName,mfaType);
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/reset")
                .then()
                .assertThat()
                .statusCode(HttpStatus.NO_CONTENT.value());
        Assertions.assertTrue(UtilsMFA.verifyMFAResetInB2C(graphEndpoint,token, liamId));
    }

    @ParameterizedTest
    @CsvSource( {"cd125785-4e0b-4290-ab4d-9d3ddf27f47f,liammfauser3@autotest.com,412,PRECONDITION_FAILED,User doesn't have MFA enabled"})
    @Order(6)
    void testResetMFAWithMFAOff(String liamId, String userName, int expectedCode, String expectedStatus, String expectedMessage) {
        disableMFA(liamId, userName);
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/reset")
                .then()
                .assertThat()
                .statusCode(expectedCode)
                .body("code", equalTo(expectedCode))
                .body("status", equalTo(expectedStatus))
                .body("message", equalTo(expectedMessage));

    }


    @Test
    void testResetMFAExpiredToken() {
        given().headers(mfaHttpHeaders)
                .header("Authorization","Bearer " + prop.getProperty("expiredJwtToken"))
                .and()
                .body(UtilsMFA.buildRequest(prop.getProperty("liamId"), prop.getProperty("username"), prop.getProperty("mfaType")))
                .when()
                .put("/reset")
                .then()
                .assertThat()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .body("code", equalTo(HttpStatus.UNAUTHORIZED.value()))
                .body("status", containsStringIgnoringCase(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                .body("message", containsString(prop.getProperty("expiredTokenMessage")));
    }

    @ParameterizedTest()
    @CsvFileSource(resources = "/testdata/testResetMFAErrorCodes.csv", numLinesToSkip = 1,delimiter='|')
    @Order(6)
    void testResetMFAErrorCodes(String liamId, String userName, int expectedCode, String expectedStatus, String expectedMessage) {

        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/reset")
                .then()
                .assertThat()
                .body("code", equalTo(expectedCode))
                .body("status", equalTo(expectedStatus))
                .body("message", equalTo(expectedMessage));
    }


    private String prepTestUser(String liamUserEndpoint, HttpHeaders userHttpHeaders, String userName ) {
        // create test user if doesn't exist
        liamId = UtilsUser.getUser(liamUserEndpoint, userHttpHeaders, userName );

        if (null == liamId){
            logger.info(userName  + "doesn't exist" );
            liamId = UtilsUser.createUser(liamUserEndpoint, userHttpHeaders, userName);
            logger.info("Created test user " + userName);
        }
        logger.info("liamId is " + liamId);
        return liamId;
    }

    private void enableMFA(String liamId, String  userName, String mfaType) {
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildRequest(liamId, userName, mfaType))
                .when()
                .put("/enable");

    }

    private void disableMFA(String liamId, String  userName) {
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/disable");

    }

    private void resetMFA(String liamId, String  userName ) {
        given()
                .headers(mfaHttpHeaders)
                .and()
                .body(UtilsMFA.buildResetRequest(liamId, userName))
                .when()
                .put("/reset");

    }

    

   

  
}