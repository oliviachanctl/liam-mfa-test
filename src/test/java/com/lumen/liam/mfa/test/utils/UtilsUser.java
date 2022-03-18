package com.lumen.liam.mfa.test.utils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.restassured.RestAssured;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONException;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.Date;
import java.util.Properties;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import org.apache.logging.log4j.Logger;

public class UtilsUser {

    //Return the liamId of a user
    public static String getUser(String endpoint, HttpHeaders headers, String userName) {
        JsonObject getUserDetailsQueryJson = new JsonObject();
        try {
            getUserDetailsQueryJson = (JsonObject) JsonParser.parseString("{\"query\":\"query{userDetails(username:\\\"" + userName + "\\\") {liamId,username}}\",\"variables\":{} }");
        } catch (JSONException e) {
           throw new RuntimeException(e.getMessage());
        };

        Response getUserDetailsResponse = given()
                .headers(headers)
                .body(getUserDetailsQueryJson.toString())
                .post(endpoint)
                .then()
                .statusCode(HttpStatus.OK.value())
                .extract().response();

        return getUserDetailsResponse.getBody().jsonPath().getString("data.userDetails.liamId");

    }


    //create user with a speciic username and return the liamId
    public static String createUser(String endpoint, HttpHeaders headers, String userName) {

        JsonObject createUserQueryJson = new JsonObject();
        try {
            createUserQueryJson = (JsonObject) JsonParser.parseString("{\"query\":\"mutation createUser ($input: LiamUserCreateInput!) { createUser(user: $input){     liamId,    username      } }  \",\"variables\":{\"input\":{\"username\":\""+userName + "\",\"firstName\":\"test\",\"lastName\":\"test\",\"displayName\":\"test test\",\"primaryPhone\":\"51960877081\",\"mobilePhone\":\"51960877082\",\"emailAddress\":\"olivia.chan@lumen.com\",\"timeZone\":\"GMT\",\"userType\":\"PORTAL\",\"jobTitle\":\"Tester\",\"companyName\":\"LIAM\",\"addressLine1\":\"Skywalker ranch, 1\",\"addressLine2\":\"Building 3\",\"city\":\"San Antonio\",\"state\":\"Texas\",\"postalCode\":\"88765\",\"country\":\"USA\",\"sendEmail\":false}}}\n");
        } catch (JSONException e) {
            throw new RuntimeException(e.getMessage());
        };

        Response createUserResponse = given()
                .headers(headers)
                .body(createUserQueryJson.toString())
                .post(endpoint)
                .then()
                .statusCode(HttpStatus.OK.value())
                .extract().response();

        return createUserResponse.getBody().jsonPath().getString("data.createUser.liamId");

    }

}