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

import org.json.simple.JSONObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * This class is responsible for resolving the port number for login command according to
 * the origin of the port and the type of login command.
 */
class ApiPortResolver {

    private static final String API_GET_PORT_SCRIPT = "api_get_port.py";
    private static final String ENVIRONMENT         = "MDS_FWDIR";
    private static final String CLISH_PATH          = "/bin/clish";

    //port on the management server
    private int port;

    //set to true if the port entered by the user
    private boolean isUserEnterPort;

    /**
     * Constructor
     *
     * @param port The port number that was given in {@link ApiClientArgs}
     * @param isUserEnterPort True if the user entered the port number (not the default value)
     */
    ApiPortResolver(int port, boolean isUserEnterPort){

        this.port = port;
        this.isUserEnterPort = isUserEnterPort;
    }

    /**
     * This function returns the relevant port number according to the following:
     * If a user entered certain port this port will be returned, otherwise
     * if the login is done to a local server, the port will be resolved by calling to a script
     * 'api_get_port.py' if the script exists on the server.
     * If the script doesn't exist tries to resolve the port by calling clish command.
     *
     * @param isRunningOnManagementServer True if the login is to local server, otherwise false
     *
     * @return The port number
     */
    int getPort(boolean isRunningOnManagementServer){

        // In case that user entered the port, or the login command is not running on the management server,
        // resolve the port from the arg
        if(isUserEnterPort || !isRunningOnManagementServer){
            return port;
        }

        int resolvedPort;

        //In case of a default port and login as root, try resolve from the get_port script
        Integer portResolvedFromScript = resolvePortFromGetPortScript();

        //The correct way is to use the api_get_port script. However we want to handle the situation where
        //this library is used on the machine, that api_get_port script doesn't exist yet.
        if (portResolvedFromScript == null) {

            //Script doesn't exist try resolve the port from clish
            Integer resolvePortFromClish = resolvePortFromClish();

            if(resolvePortFromClish == null){
                //Failed resolving port from clish return the default port
                return port;
            }
            else{
                resolvedPort = resolvePortFromClish;
            }
        }
        else {
            resolvedPort = portResolvedFromScript;
        }

        return resolvedPort;
    }

    /**
     * This function resolves the port from clish by running the command
     * '/bin/clish -c 'show web ssl-port' -o 'structured'
     *
     * @return On success port number, otherwise null.
     */
    private Integer resolvePortFromClish(){

        //check that the clish path is file
        Path clishPath = Paths.get(CLISH_PATH);

        if (!Files.exists(clishPath)) {
            return null;
        }
        //build the process
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(CLISH_PATH, "-c",
                                                                         "show web ssl-port", "-o", "structured"));
        processBuilder.redirectErrorStream(true);
        Process process;
        try {
            //run the command
            process = processBuilder.start();
        }
        catch (IOException e) {
            throw new ApiClientRunTimeException("Error occurred while running 'api_get_port.py'"+ e.getMessage());
        }

        InputStream inputStream = process.getInputStream();
        if (inputStream == null) {
            throw new ApiClientRunTimeException("Can't read API external port, input stream is undefined");
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            String line = reader.readLine();
            //the answer is in format web-ssl-port;port-number;
            String [] portNumber = line.split(";");

            if(portNumber.length != 2){
                return null;
            }
            return Integer.parseInt(portNumber[1]);
        }
        catch (IOException  | NumberFormatException e ) {
            throw new ApiClientRunTimeException("Can't read API external port");
        }
    }

    /**
     * This function resolves the port number, using the api_get_port.py script
     *
     * @return port number
     */
    private Integer resolvePortFromGetPortScript() throws ApiClientRunTimeException {

        String mdsFwdir = System.getenv(ENVIRONMENT);
        //MDS_FWDIR environment variable not defined
        if (mdsFwdir == null || mdsFwdir.isEmpty()) {
            return null;
        }
        //find the get_port script
        Path workingDirPath = Paths.get(mdsFwdir, "Python", "bin");
        //Python working directory was not found at mdsFwdir/Python/bin
        if (!Files.exists(workingDirPath)) {
            return null;
        }

        Path pythonExec = Paths.get(workingDirPath.toString(), "python");
        // Python executable was not found at mdsFwdir/Python/bin/python
        if (!pythonExec.toFile().exists()) {
            return null;
        }

        Path getPortScript = Paths.get(mdsFwdir, "scripts", API_GET_PORT_SCRIPT);
        //The script wasn't find
        if (!getPortScript.toFile().exists()) {
            return null;
        }

        int port;

        //Run the get_port script
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(pythonExec.toString(),
                                                                         getPortScript.toString(), "-f", "json"));
        processBuilder.directory(workingDirPath.toFile());
        processBuilder.redirectErrorStream(true);
        Process process;

        try {
            process = processBuilder.start();
        }
        catch (IOException e) {
           throw new ApiClientRunTimeException("Error occurred while running 'api_get_port.py'"+ e.getMessage());
        }

        InputStream inputStream = process.getInputStream();
        if (inputStream == null) {
            throw new ApiClientRunTimeException("Can't read API external port, input stream is undefined");
        }

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }

            String portString = (((JSONObject)UtilClass.convertToJson(output.toString())).get("external_port")).toString();
            port = Integer.parseInt(portString);
        }
        catch (IOException | NumberFormatException e) {
            throw new ApiClientRunTimeException("Can't read API external port");
        }

        return port;
    }

    /**
     * This function sets the current port to given port number.
     *
     * @param port The port of Management Server. (null to initialize the port to the default port)
     */
    void setPort(Integer port)
    {
        if (port == null){
            isUserEnterPort = false;
            this.port = ApiClient.DEFAULT_PORT;
        }
        else{
            isUserEnterPort = true;
            this.port = port;
        }
    }
}