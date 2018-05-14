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

package com.checkpoint.mgmt_api.client;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.MessageFormat;
import java.util.Scanner;

public final class UtilClass {

    private UtilClass()
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Convert string to JsonObject
     *
     * @param string The string that we want to convert to json-object
     *
     * @return {@link JSONObject} that contains the string in json format
     */
    public static Object convertToJson(String string){

        JSONParser parser = new JSONParser();
        Object obj;

        if(string == null || string.isEmpty() ){
            throw new ApiClientRunTimeException("Error: failed to get string data");
        }

        try {
            obj = parser.parse(string);
        } catch (ParseException e) {
            throw new ApiClientRunTimeException("Error: failed to get string data");
        }

        if(obj == null){
            throw new ApiClientRunTimeException("Error: failed to get string data");
        }

        return obj;
    }

    /**
     * This method reads the response from a given process, and returns string contains the response.
     *
     * @param process
     *
     * @return The response.
     *
     * @throws ApiClientRunTimeException if error occurs while reading response from process
     */
    static String getResponseFromProcess(Process process) throws ApiClientRunTimeException {

        StringBuilder responseBody = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))){
            String line;
            while ((line = reader.readLine()) != null) {
                responseBody.append(line);
            }
        }catch (IOException e ){
            throw new ApiClientRunTimeException("Error: failed receive the response from the server");
        }
        return responseBody.toString();
    }

    /**
     * @param version1 The version separated with dots
     * @param version2 The version separated with dots
     *
     * @return The value 1 if version1 is more advance than version 2
     * value -1 if version2 is more advance
     * value 0 if they are equal.
     * @throws NumberFormatException
     */
    public static int compareVersions(String version1, String version2)
    {
        return version1.compareTo(version2);
    }

    public static void verifyServerFingerprint(ApiClient client, boolean loginAsRoot, String server) throws ApiClientException{
        verifyServerFingerprint( client, loginAsRoot, server, 443);
    }

    /**
     * In case loginAsRoot set to True:
     *      The function compares the server's fingerprint and the server's fingerprint from the 'api fingerprint' call.
     * otherwise:
     *      The function compares the server's fingerprint and the server's fingerprint written in the file for equality.
     *      If they are equal, the function does noting, but if they are not, the function asks the user if
     *      he wishes to save the server's fingerprint to the file.
     *      If the answer is yes, the function adds the server's fingerprint to the file.
     *      If the answer is no, the function does noting.
     *
     * @param client {@link ApiClient}
     * @param loginAsRoot True if login is as root (running on the management server)
     * @param serverIpAddress  The IP address or name of the Check Point Management Server
     * @param port Port Number
     *
     * @throws ApiClientException
     */
    public static void verifyServerFingerprint(ApiClient client, boolean loginAsRoot, String serverIpAddress, int port) throws ApiClientException{

        if (loginAsRoot){
            serverIpAddress = ApiClient.LOCAL_SERVER_IP;
        }

        boolean addFingerprintToFile = false;

        //Get the server's fingerprint
        String fingerprint = client.getFingerprintManager().getServerFingerprint(serverIpAddress, port);

        if (fingerprint == null) {
            throw new ApiClientException("Could not get the server's fingerprint - Check connectivity with the server. " +
                                        "Check 'api status' for more details.");
        }

        // The API client looks for the server's certificate SHA1 fingerprint in a file.
        String fingerprintFromFile = null;

        try {

            fingerprintFromFile = client.getFingerprintManager().getFingerprintFromFile(serverIpAddress, port);
        } catch (ApiClientException e) {
            System.out.println(e.getMessage());
        }

        if(!loginAsRoot) {
            addFingerprintToFile = askUserToApproveFingerprint(fingerprintFromFile, fingerprint, serverIpAddress);
        }
        else if (fingerprintFromFile == null || !fingerprintFromFile.equalsIgnoreCase(fingerprint)) {
                validateServerFingerprintInLoginAsRootCase(client, fingerprint);
                addFingerprintToFile = true;
        }

        //Adding the fingerprint to the file
        if(addFingerprintToFile) {
            try {
                    client.getFingerprintManager().saveFingerprintToFile(serverIpAddress, fingerprint, port);
            } catch (ApiClientException e) {

                throw new ApiClientException("Failed to write fingerprint to the file. Error: " + e.getMessage());
            }
        }
    }

    /**
     * This function compares the server's fingerprint and the server's fingerprint written in the
     * file for equality.
     * If they are equal, the function does noting, but if they are not, the function asks the user if
     * he wishes to save the server's fingerprint to the file.
     * If the answer is no, the function throws an exception
     *
     * @param fingerprintFromFile Server's fingerprint
     * @param fingerprint Server's fingerprint written in the file .
     * @param serverIpAddress The IP address or name of the Check Point Management Server
     *
     * @return True if the the new fingerprint need to be saved in the fingerprint file. Otherwise False
     *
     * @throws ApiClientException In case of error or unproved fingerprint
     */
    public static boolean askUserToApproveFingerprint(String fingerprintFromFile, String fingerprint,
                                                      String serverIpAddress) throws ApiClientException
    {
        // fingerprint file doesn't contains server fingerprint
        if (fingerprintFromFile == null) {
            // first connection to the server
            String messageToAsk = MessageFormat.format(
                    "First connection to the server {0} \n\nTo verify server identity, compare the" +
                            " following fingerprint with the one displayed by the api management tool" +
                            " <api fingerprint>.\n\nSHA1 Fingerprint = {1}\n\n"
                            ,serverIpAddress,
                            printFingerprint(fingerprint.toUpperCase()));

            String messageIfNotApproved = "First connection to the server and the fingerprint wasn't approved ";
            return askUserTheQuestion(messageToAsk, messageIfNotApproved);
        }
        // fingerprint file contains server fingerprint and fingerprint from file does't match the fingerprint of server
        else if (!fingerprintFromFile.equalsIgnoreCase(fingerprint)) {
                    // fingerprint has  changed
                    String messageToAsk = MessageFormat.format(
                            "Fingerprint of server {0} was changed.\n\nTo protect server against impersonation, " +
                                    "compare the following fingerprint with the one displayed by the api management tool" +
                                    " <api fingerprint>.\n\nSHA1 Fingerprint = {1}\n\n",
                            serverIpAddress,
                            printFingerprint(fingerprint.toUpperCase()));
                    String messageIfNotApproved = "Fingerprint of server was changed and the new fingerprint wasn't approved ";
                    return askUserTheQuestion(messageToAsk, messageIfNotApproved);
        }
        return false;
    }

    /**
     * This function asks user a given message and waits for user answer.
     *
     * @param messageToAsk The message need to be asked
     * @param messageIfNotApproved The message that will throw in a case of negative answer.
     *
     * @return On positive answer ('y') the function return true, otherwise throws exception.
     *
     * @throws ApiClientException
     */
    private static boolean askUserTheQuestion(String messageToAsk, String messageIfNotApproved)throws ApiClientException{
        System.out.println(messageToAsk);
        if (askYesNoQuestion("Do you accept the fingerprint?")) {
            return true;
        }
        else {
            System.out.println(messageIfNotApproved);
            throw new ApiClientException(messageIfNotApproved);
        }
    }

    /***
     * This function compares the server's fingerprint and the server's fingerprint from the 'api fingerprint' command
     * for equality.
     *
     * @param client the {@link ApiClient}
     * @param fingerprint the server's fingerprint
     *
     * @throws ApiClientException if the server's fingerprint doesn't match server's fingerprint from
     * the 'api fingerprint' command.
     */
    public static void validateServerFingerprintInLoginAsRootCase(ApiClient client, String fingerprint)
            throws ApiClientException{

        JSONArray fingerprintsFromApiFingerprint;
        try {
            fingerprintsFromApiFingerprint = client.getFingerprintManager().getFingerprintFromApiFingerprintUtil();
        }catch (ApiClientRunTimeException e) {
            String messageToPrint = "Failed to read fingerprint from 'api fingerprint -f json' command.";
            System.out.println(messageToPrint);
            String message = messageToPrint + " Error message: " + e.getMessage();
            throw new ApiClientException(message);
        }

        if (fingerprintsFromApiFingerprint == null){
            String message = "Failed to read fingerprint from 'api fingerprint -f json' command.";
            System.out.println(message);
            throw new ApiClientException(message);
        }
        // Go over all fingerprints
        for (Object fingerprintObject : fingerprintsFromApiFingerprint) {
            JSONObject fingerprintFromApiFingerprint = (JSONObject) fingerprintObject;
            if (!fingerprintFromApiFingerprint.containsKey(FingerprintManager.FINGERPRINT_KEY)) {
                String message = "Fingerprint wasn't approved. Parsing 'api fingerprint' response " +
                        "failed, missing key 'fingerprint-sha1'";
                System.out.println(message);
                throw new ApiClientException(message);
            }
            String sha1 = fingerprintFromApiFingerprint.get(FingerprintManager.FINGERPRINT_KEY).toString();
            if (sha1.equalsIgnoreCase(fingerprint)) {
                // Found a match, write the fingerprint to file
                return;
            }
        }

        String message = "Fingerprint wasn't approved. The fingerprint does not match to the fingerprints from" +
                " the 'api fingerprint' command";
        System.out.println(message);
        throw new ApiClientException(message);
    }

    /**
     * Returns the given fingerprint string with ":" after every two characters
     *
     * @param fingerprint The fingerprint
     *
     * @return The string that represent the fingerprint with ":" after every two characters
     */
    private static String printFingerprint(String fingerprint){

        StringBuilder str = new StringBuilder(fingerprint);
        int index         = str.length() - 2;

        while (index > 0)
        {
            str.insert(index, ":");
            index = index - 2;
        }

        return str.toString();
    }

    /**
     * Utility function. Presents a question to the user with Y/N options.
     *
     * @param question The question to ask the user
     *
     * @return true if the user gave 'Y' otherwise false is returned
     */
    public static boolean askYesNoQuestion(String question) {

        Scanner input  = new Scanner(System.in);
        String message = question + " [Y/N] ";
        System.out.println(message);

        String a = input.next();
        return a.equalsIgnoreCase("y");
    }
}
