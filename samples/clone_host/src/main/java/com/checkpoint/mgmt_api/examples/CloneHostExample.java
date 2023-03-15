/**
 * Copyright © 2016 Check Point Software Technologies Ltd.  All Rights Reserved.
 * Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee and without a signed licensing agreement, is hereby
 * granted, provided that the above copyright notice, this paragraph and the following three paragraphs appear in all copies, modifications, and distributions.
 *
 * CHECK POINT DOES NOT PROVIDE, AND HAS NO OBLIGATION TO PROVIDE, MAINTENANCE SERVICES, TECHNICAL OR CUSTOMER SUPPORT, UPDATES,
 * ENHANCEMENTS, OR MODIFICATIONS FOR THE SOFTWARE OR THE DOCUMENTATION.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE SOFTWARE AND DOCUMENTATION IS PROVIDED ON AN "AS IS," "AS AVAILABLE" AND "WHERE-IS"
 * BASIS.  ALL CONDITIONS, REPRESENTATIONS AND WARRANTIES WITH RESPECT TO THE SOFTWARE OR ITS DOCUMENTATION, WHETHER EXPRESS, IMPLIED, STATUTORY
 * OR OTHERWISE, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT OF THIRD PARTY
 * RIGHTS, ARE HEREBY DISCLAIMED.
 *
 *IN NO EVENT SHALL CHECK POINT BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF CHECK POINT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.checkpoint.mgmt_api.examples;

import com.checkpoint.mgmt_api.client.*;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.text.MessageFormat;

/**
 * This class creates a new host object with a new given ip address and adds it to all the
 * groups and access rules to which the original host belongs to.
 */
public class CloneHostExample {

    public static void main(String[] args) {

        //---------------------------------//
        //Program input

        //Management server IP address
        String server = "127.0.0.1";
        String cloudMgmtId = "aa3ce335-801a-4fc4-ba78-56cd20300d50";

        //Login credentials
        String username = "username";
        String password = "password";
        String apiKey = "api-key";

        //The name of the original Host object to be cloned
        String origHost = "originalHost";

        //The name of the host that is created by cloning the original host
        String clonedHost = "newHost";

        //IP address of the new host
        String clonedIp = "192.0.2.0";
        //------------------------------------//

        //Set the argument for the ApiClient constructor
        ApiClientArgs arguments = new ApiClientArgs();
        arguments.setDebugFile("debugFile.txt");

        ApiClient client = new ApiClient(arguments);

        try {
            UtilClass.verifyServerFingerprint(client, false, server);
        }
        catch (ApiClientException e){
            System.out.println(e.getMessage());
            printInErrorAndExit(null, client, false);
        }

        // Login to server
        ApiLoginResponse loginResponse = null;
        JSONObject loginPayload        = new JSONObject();
        loginPayload.put("user", username);
        loginPayload.put("password",password);
        loginPayload.put("api-key", apiKey);

        try {
            loginResponse = client.login(server, loginPayload, cloudMgmtId);
        } catch (ApiClientException e) {
            System.out.println(e.getMessage());
                System.exit(1);
            }
        if (loginResponse == null || !loginResponse.isSuccess()) {
            System.out.println("Login failed.");
            printInErrorAndExit(loginResponse, loginResponse, client, false);
        }

        // Create host
        JSONObject directUsages = whereHostUsedDirectly(client, loginResponse, origHost, clonedHost);
        createHost(loginResponse,client, origHost, clonedHost, clonedIp);
        copyReference(loginResponse,client, origHost, clonedHost, directUsages);

        //Exit the client
        try {
            client.exit(loginResponse);
        } catch (ApiClientException e) {
            System.out.println ("Failed exiting client. Error message: " + e.getMessage());
        }
    }

    /**
     * This function returns where the cloned object is been used by directly by calling where-used command.
     *
     * @param client {@link ApiClient} that makes the call
     * @param loginResponse The {@link ApiLoginResponse} response of the login command.
     * @param origHost the original host's name that the function clone
     * @param clonedHost the new host's name
     *
     * @return {@link JSONObject} contain all the the direct usage of the original host
     */
    private static JSONObject whereHostUsedDirectly(ApiClient client, ApiLoginResponse loginResponse, String origHost, String clonedHost){

        ApiResponse whereUsed = getWhereHostUsed(client, loginResponse, origHost);

        JSONObject directUsages = null;
        try {
            directUsages = (JSONObject) whereUsed.getPayload().get("used-directly");
        //if the object is not being referenced there is nothing to do.
        if (directUsages.get("total").toString().equals("0")) {
            System.out.println(origHost + " is not in use! nothing to do");
                    printInErrorAndExit(loginResponse, client, false);
            }
        }
        catch (Exception e) {
            System.out.println("Error: couldn't get 'use directly' data', Message:" + e.getMessage());
        }
        //Print all unsupported references (i.e. references that which  are not copied to the new object)
        boolean hasUnsupportedReference = printUnsupportedReferences(client, origHost, clonedHost, directUsages);

        //Checks if there are no unsupported references or the user decides to continue in any case
        if (hasUnsupportedReference &&
                !UtilClass.askYesNoQuestion(MessageFormat.format(
                        "The above list of reference(s) for host {0} will not be cloned to {1}! Continue anyway? ",
                        origHost,
                        clonedHost))) {
            printInErrorAndExit(loginResponse, client, false);
        }

        return directUsages;
    }

     /**
     * This function returns where the cloned object is been used by calling where-used command.
     *
     * @param client {@link ApiClient} that makes the call
     * @param loginResponse The {@link ApiLoginResponse} response of the login command.
     * @param origHost The original host's name that the function clones
     *
     * @return The {@link ApiResponse} from 'where used' command on the original host
     */
    private static ApiResponse getWhereHostUsed(ApiClient client, ApiLoginResponse loginResponse, String origHost){

        JSONObject json = new JSONObject();
        json.put("name", origHost);
        ApiResponse whereUsed = null;

        try {
            whereUsed = client.apiCall(loginResponse,"where-used", json);
        } catch (ApiClientException e) {
            System.out.println("Failed to get " + origHost + " data. Error" + e.getMessage());
            printInErrorAndExit(loginResponse, whereUsed, client, false);
        }

        if (whereUsed == null || !whereUsed.isSuccess()) {

            System.out.println("Failed to get " + origHost + " data. ");
            printInErrorAndExit(loginResponse, whereUsed, client, false);
        }

        return whereUsed;
    }

    /**
     * Add newHost to the same groups and access-rules that origHost belongs to
     *
     * @param client {@link ApiClient} that makes the call
     * @param origHost The original host's name that the function clones
     * @param newHost The new host's name
     * @param whereUsedData {@link JSONObject} that contain the places the original host belongs to
     */
    private static void copyReference(ApiLoginResponse loginResponse,ApiClient client, String origHost,
                                      String newHost, JSONObject whereUsedData) {
        //handle group objects
        if (whereUsedData.containsKey("objects")) {
            copyGroupsReference(client, loginResponse, whereUsedData, newHost);
        }

        // handle access rules
        if (whereUsedData.containsKey("access-control-rules")) {
            copyAccessRuleReference(client, loginResponse, whereUsedData, origHost, newHost);

        }

        //we're done. call 'publish'
        ApiResponse publish = null;
            try {
            publish = client.apiCall(loginResponse, "publish", "{}");
            } catch (ApiClientException e) {
            System.out.println("\nPublished failed. Aborting all changes. Error: " + e.getMessage());
            printInErrorAndExit(loginResponse, publish, client, true);
        }
        if (publish == null || !publish.isSuccess()) {

            System.out.println("\nPublished failed. Aborting all changes.");
            printInErrorAndExit(loginResponse, publish, client, true);
        }
    }

    /**
     * Add newHost to the same groups that origHost belongs to
     *
     * @param client {@link ApiClient} that makes the call
     * @param loginResponse The {@link ApiLoginResponse} response of the login command.
     * @param whereUsedData The data of 'where used' on the origHost response
     * @param newHost The new host's name
     */
    private static void copyGroupsReference(ApiClient client, ApiLoginResponse loginResponse,
                                            JSONObject whereUsedData, String newHost){
        JSONArray whereUsedObjects = (JSONArray) whereUsedData.get("objects");
        for (Object whereUsedObj : whereUsedObjects) {

            JSONObject whereUsedObjData = (JSONObject) whereUsedObj;
            if (whereUsedObjData.get("type").toString().equals("group")) {

                System.out.println("Adding " + newHost + " to group " + whereUsedObjData.get("name"));
                String payload = "{\"name\" : \"" + whereUsedObjData.get("name").toString() + "\", \"members\" : {\"add\" : \"" +
                                            newHost + "\"}}";
                ApiResponse setGroupRes = null;
                    try {
                    setGroupRes = client.apiCall(loginResponse, "set-group", payload);
                }
                catch (ApiClientException e) {
                    System.out.println("\nOperation failed. Aborting all changes. Error: " + e.getMessage());
                    printInErrorAndExit(loginResponse, setGroupRes, client, true);
                    }
                if (setGroupRes == null || !setGroupRes.isSuccess()) {

                    System.out.println("\nOperation failed. Aborting all changes.");
                    printInErrorAndExit(loginResponse, setGroupRes, client, true);
                    }
                }
            }
        }

    /**
     * Add newHost to the same access-rules that origHost belongs to
     *
     * @param client {@link ApiClient} that makes the call
     * @param loginResponse The {@link ApiLoginResponse} response of the login command.
     * @param whereUsedData The data of 'where used' on the origHost response
     * @param origHost The original host's name that the function clones
     * @param newHost The new host's name
     */
    private static void copyAccessRuleReference(ApiClient client, ApiLoginResponse loginResponse,
                                                JSONObject whereUsedData, String origHost, String newHost){

        JSONArray accessRules = (JSONArray) whereUsedData.get("access-control-rules");
        for (Object accessRuleObj : accessRules) {

            JSONObject accessRule = (JSONObject) accessRuleObj;
            JSONObject places = isHostObjectInRuleSourceOrDestination(
                    loginResponse, client, origHost, ((JSONObject) accessRule.get("layer")).get("name").toString(),
                    ((JSONObject) accessRule.get("rule")).get("uid").toString());

            System.out.println("Adding " + newHost + " to rule number " + accessRule.get("position").toString() +
                                       " in policy " + ((JSONObject) accessRule.get("package")).get("name").toString() +
                                       "(layer: " + ((JSONObject) accessRule.get("layer")).get("name").toString() + ")");

                if ((boolean)places.get("source")) {

                String payload = "{\"uid\" : \"" + ((JSONObject) accessRule.get("rule")).get("uid")
                        + "\", \"layer\" : \"" + ((JSONObject) accessRule.get("layer")).get("name")
                        + "\", \"source\" : {\"add\" :\"" + newHost + "\"}}";

                setAccessRule(loginResponse, payload, client);
                }

                if ((boolean)places.get("destination")) {

                String payload = "{\"uid\" : \"" + ((JSONObject) accessRule.get("rule")).get("uid") +
                        "\", \"layer\" : \"" + ((JSONObject) accessRule.get("layer")).get("name") +
                        "\",\"destination\" : {\"add\" :\"" + newHost + "\"}}";
                setAccessRule(loginResponse, payload, client);
            }
                    }
                }

    /**
     *This function sets the access-rule accordingly to the given payload
     * @param payload arguments for the set-access-rule command
     * @param client {@link ApiClient} that makes the call
     * @param loginResponse The {@link ApiLoginResponse} response of the login command.
     */
    private static void setAccessRule( ApiLoginResponse loginResponse, String payload, ApiClient client){
        ApiResponse setAccessRes = null;

        try {
            setAccessRes = client.apiCall(loginResponse, "set-access-rule", payload);
        } catch (ApiClientException e) {
            System.out.println("\nOperation set-access-rule failed. Aborting all changes.");
            printInErrorAndExit(loginResponse, setAccessRes, client, true);
        }
        if (setAccessRes == null || !setAccessRes.isSuccess()) {

            System.out.println("\nOperation set-access-rule failed. Aborting all changes.");
            printInErrorAndExit(loginResponse, setAccessRes, client, true);
        }
    }

    /**
     * This function will indicate if the host is in the source, destination or both.
     *
     * @param client {@link ApiClient}that making the call
     * @param host host that the function check if it appears in the source/destination of the rule
     * @param layerName the layer in the rule
     * @param ruleUid the rule id
     *
     * @return JsonObject thar contain to keys: 1.source the value is true
     *          if the host belongs the rule source,else false.
     *          2.destination the value is true if the host belongs the rule source, else false.
     */
    private static JSONObject isHostObjectInRuleSourceOrDestination(ApiLoginResponse loginResponse,ApiClient client,
                                                                    String host, String layerName, String ruleUid) {
        JSONObject res = new JSONObject();
        res.put("source", false);
        res.put("destination", false);

        ApiResponse ruleInfo = null;
        try {
            ruleInfo = client.apiCall(loginResponse,"show-access-rule", "{\"uid\":\""
                                        + ruleUid+"\",\"layer\":\"" + layerName+"\"}");
        } catch (ApiClientException e) {
            System.out.println("\nFailed to get rule details. Error: " + e.getMessage());
            printInErrorAndExit(loginResponse, ruleInfo, client, true);
        }

        if (ruleInfo == null || !ruleInfo.isSuccess()) {
            System.out.println("\nFailed to get rule details.");
            printInErrorAndExit(loginResponse, ruleInfo, client, true);
        }

        //is the host in the source
        JSONArray array = (JSONArray) ruleInfo.getPayload().get("source");
        for (Object anArray : array) {
            JSONObject object = (JSONObject) anArray;
            if (object.get("name").toString().equals(host)) {
                res.remove("source");
                res.put("source", true);
            }
        }

        //is the host in the destination?
        array = (JSONArray) ruleInfo.getPayload().get("destination");
        for (Object anArray : array) {
            JSONObject object = (JSONObject) anArray;
            if (object.get("name").toString().equals(host)) {
                res.remove("destination");
                res.put("destination", true);
            }
        }
        return res;
    }

    /**
     * This function is for logging purposes only it prints a list of unsupported references that the
     * original host belongs.
     * Go over all the different references that the whereUsed API is pointing to. If the reference is not a group
     * or an access rule, report it as an unsupported type.
     *
     * @param client {@link ApiClient}that making the call
     * @param origHost the original host's name that the function clone
     * @param newHost the new host's name
     * @param whereUsedData JSonObject that contain the places the original host belongs to
     *
     * @return True if there are unsupported references to the orgHost, otherwise  False.
     */
    private static boolean printUnsupportedReferences(ApiClient client, String origHost, String newHost,
                                                        JSONObject whereUsedData) {
        boolean hasUnsupportedReference = false;

        //go over objects
        if (whereUsedData.containsKey("objects")) {
            JSONArray array = (JSONArray) whereUsedData.get("objects");
            for (Object anArray : array) {
                JSONObject obj = (JSONObject) anArray;
                if(!obj.get("type").toString().equals("group")) {
                    hasUnsupportedReference = true;
                    System.out.println(newHost + " is referenced by " + obj.get("name") + ", Type: " + obj.get("type"));
                }
            }
        }

        //threat prevention rules
        if ( !((JSONArray) whereUsedData.get("threat-prevention-rules")).isEmpty() ) {
            System.out.println(origHost + " is referenced by Threat prevention rule(s)/exception(s)");
            JSONArray array = (JSONArray) whereUsedData.get("threat-prevention-rules");
            for (Object anArray : array) {
                JSONObject obj = (JSONObject) anArray;
                hasUnsupportedReference = true;
                System.out.println("Policy Package: " + ((JSONObject) obj.get("package")).get("name").toString() +
                                        " ,Rule number: " + obj.get("position").toString());
            }
        }

        // nat-rules
        if (!((JSONArray)whereUsedData.get("nat-rules")).isEmpty()) {
            System.out.println(origHost + " is referenced by NAT rule(s)");
            JSONArray array = (JSONArray) whereUsedData.get("nat-rules");
            for (Object anArray : array) {
                JSONObject obj = (JSONObject) anArray;
                hasUnsupportedReference = true;
                System.out.println("Policy Package: " + ((JSONObject) obj.get("package")).get("name").toString() +
                                        " ,Rule number: " + obj.get("position").toString());
            }
        }
        return hasUnsupportedReference;
    }

    /**
     * Create a new host object with the given newName as its name and IP address newIpAddress.
     * The color and comments of the original host are copied to the newly created host.
     *
     * @param client {@link ApiClient}that making the call
     * @param origHost  The host that is been copied
     * @param newHostName  New host name
     * @param newIpAddress New host IP address
     */
    private static void createHost(ApiLoginResponse loginResponse,ApiClient client, String origHost,
                                   String newHostName, String newIpAddress) {
        //get details of existing object
        ApiResponse showHostRes = null;
        try {
            showHostRes = client.apiCall(loginResponse, "show-host", "{\"name\" :\""+ origHost +"\"}");
        } catch (ApiClientException e) {
            System.out.println("Failed to get data of existing host. Aborting. Error: " +e.getMessage());
            printInErrorAndExit(loginResponse, showHostRes, client, true);
        }
        if (showHostRes == null || !showHostRes.isSuccess()) {
            System.out.println("Failed to get data of existing host. Aborting.");
            printInErrorAndExit(loginResponse, showHostRes, client, true);
        }

        String color    = showHostRes.getPayload().get("color").toString();
        String comments = showHostRes.getPayload().get("comments").toString();

        // create the new object
        System.out.println("\nCreating new host " + newHostName);

        ApiResponse addHostRes = null;
        try {
            //ApiCall may receive either JSON object or string in valid JSON format
            addHostRes = client.apiCall(loginResponse, "add-host", "{\"name\" :\"" + newHostName + "\", \"ip-address\" :\"" +
                    newIpAddress + "\", \"color\" :\"" + color + "\", \"comments\":\"" + comments + "\"}");
        } catch (ApiClientException e) {
            System.out.println("\nFailed to add new host. Error: " + e.getMessage());
            printInErrorAndExit(loginResponse, addHostRes, client, true);
        }

        //exit in case of an error
        if (addHostRes == null || !addHostRes.isSuccess()) {
            System.out.println("\nOperation failed. Aborting all changes.");
            printInErrorAndExit(loginResponse, addHostRes, client, true);
        }
    }

    /**
     * This function exit the program properly in case of errors:
     * (1) prints errors and warning message if exist
     * (2) do discard when needed
     * (3) run 'exit' function, that saves the logs to the debug file.
     *
     * @param loginResponse The {@link ApiLoginResponse} - the response of the login command.
     * @param client {@link ApiClient}that making the call
     * @param discard If set to True the function does "discard" to the changes.
     */
    private static void printInErrorAndExit(ApiLoginResponse loginResponse, ApiClient client, boolean discard){
        printInErrorAndExit(loginResponse, null, client, discard);
    }

    /**
     * This function exit the program properly in case of errors:
     * (1) prints errors and warning message if exist
     * (2) do discard when needed
     * (3) run 'exit' function, that saves the logs to the debug file.
     *
     *  @param loginResponse The {@link ApiLoginResponse} - the response of the login command.
     * @param response The response that
     ** @param client {@link ApiClient}that making the call
     * @param discard If set to True the function does "discard" to the changes.
     */
    private static void printInErrorAndExit(ApiLoginResponse loginResponse, ApiResponse response, ApiClient client, boolean discard){

        if(response != null && response.getErrors()!= null){
            System.out.println("Errors: " + response.getErrors().toString());
        }
        if(response != null && response.getWarnings()!= null){
            System.out.println("Warning: " + response.getWarnings().toString());
        }
        if(discard) {
            try {
                client.apiCall(loginResponse,"discard", "{}");
            } catch (ApiClientException e) {
                e.printStackTrace();
            }
        }
        try {
            //Exit the client
            if(loginResponse != null) {
            client.exit(loginResponse);
            }
        } catch(ApiClientException e) {
            System.out.println ("Failed exiting, "+e.getMessage());
        }
        System.exit(1);
    }
}

