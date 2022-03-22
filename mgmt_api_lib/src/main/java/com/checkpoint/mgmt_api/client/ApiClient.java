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
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import javax.net.ssl.*;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * The ApiClient Class provides basic methods to utilize the REST Web Service of the Check Point Management server.
 *
 * Summary of the principal methods:
 * (1) login                 - execute a login command
 * (2) apiCall               - execute a given command
 * (3) apiQuery              - return all the objects of a specific Query (should be used when there are a lot of objects)
 * (4) handleAsyncTaskAsSync - returns only when all of the processes and sub-processes of a given task have terminated
 * (5) exit                  - execute a logout command
 */
public class ApiClient {

    static final String URL_PROTOCOL                    = "https";
    static final String CONTEXT                         = "/web_api/";
    static final String TRANSPORT_LAYER_SECURITY        = "TLSv1.2";
    public static final String DEFAULT_FINGERPRINT_FILE = "./fingerprints.txt";
    public static final String LOCAL_SERVER_IP          = "127.0.0.1";

    private static final String SHOW_TASK_COMMAND       = "show-task";
    private static final String USER_AGENT              = "java-api-wrapper";
    private static final String IN_PROGRESS             = "in progress";
    private static final String SID_HEADER              = "X-chkp-sid";
    private static final String LOGIN_CMD               = "login";
    private static final String MGMT_CLIENT_EXEC        = "CPDIR";
    private static final String CONTEXT_LOGIN_AS_ROOT   = "/bin/mgmt_cli";

    public static final int DEFAULT_PORT              = 443;
    private static final int LIMIT                    = 50;
    private static final int ASYNC_TASK_SLEEP_SECONDS = 2;
    private static final int OK_RESPONSE_CODE         = 200;
    private static final int TIMEOUT_CONNECTION_SEC   = 180;
    private static final int READ_CONNECTION_SEC      = 300;

    private final FingerprintManager fingerprintManager;

    //If set to True, will validate the server's fingerprint
    private boolean checkFingerprint;

    //Path to the debug file. Logs all of the API calls
    private Path debugFile;

    //The settings for tunneling through a proxy
    private ApiProxySettingsProcessor proxySettings;

    private int limitQuery = LIMIT;

    //Responsible for resolving the port
    private ApiPortResolver portResolver;

    /**
     * Constructor.
     */
    public ApiClient(){
        this(new ApiClientArgs());
    }

    /**
     * Constructor.
     *
     * @param args Arguments for the constructor.
     *             Contains the fingerprint file name, the debug file name and the checkFingerprint status
     * */
    public ApiClient(ApiClientArgs args) {

        if(args == null){
            throw new ApiClientRunTimeException("ERROR: input is invalid");
        }

        checkFingerprint     = args.isCheckFingerprint();
        proxySettings        = new ApiProxySettingsProcessor(args.getProxySetting());
        portResolver         = new ApiPortResolver(args.getPort(),args.isUserEnteredPort());
        fingerprintManager   = new FingerprintManager(args.getFingerprintFile(), proxySettings);

        if(args.getDebugFile() != null){
            setDebugFile(args.getDebugFile());
        }
    }

    /**
     * This function uses the login command to login into the management server.
     *
     * @param serverIpAddress The IP address or name of the Check Point Management Server.
     * @param payload String representing a JSON object containing the login command's arguments.
     *
     * @return {@link ApiResponse} object
     *
     * @throws ApiClientException if error occurs while preforming an API call
     */
    public ApiLoginResponse login(String serverIpAddress, String payload) throws ApiClientException {

        if(serverIpAddress == null || serverIpAddress.isEmpty()){
            throw new ApiClientException("Error: server IP address is invalid");
        }

        int port = portResolver.getPort(false);
        ApiLoginResponse loginResponse = new ApiLoginResponse(serverIpAddress , OK_RESPONSE_CODE, port, new JSONObject());
        return (ApiLoginResponse) apiCall(loginResponse,"login", payload);
    }

    /**
     * This function uses login command to login into the management server.
     *
     * @param serverIpAddress The IP address or name of the Check Point Management Server.
     * @param payload JSON object containing the login command's arguments.
     *
     * @return {@link ApiResponse} object
     *
     * @throws ApiClientException if error occurs while preforming an API call
     */
    public ApiLoginResponse login(String serverIpAddress, JSONObject payload) throws ApiClientException {

        if(payload == null){
            throw new ApiClientException("Error: payload is invalid");
        }
        String pay = payload.toString();
        return login(serverIpAddress,pay);
    }

    /**
     * This method allows to login into the management server with Root permissions.
     * In order to use this method the application should be run directly on the Management Server
     * and to own super-user privileges.
     *
     * @param payload JSON object containing the login command's arguments.
     *
     * @return {@link ApiResponse} object
     *
     * @throws ApiClientRunTimeException if error occurs while invoking login as root
     */
    public ApiLoginResponse loginAsRoot( JSONObject payload) {

        Path pathFile;
        ApiLoginResponse loginResponse;
        String systemEnvironment = System.getenv(MGMT_CLIENT_EXEC);

        //checks
        if(systemEnvironment == null)
        {
            throw new ApiClientRunTimeException("Failed to login as root, you are not running " +
                                                    "on the Management Server");
        }
        else{
            pathFile = Paths.get(systemEnvironment, CONTEXT_LOGIN_AS_ROOT);
            //java.nio build Path and then Files.exists()
            if(!Files.exists(pathFile)|| Files.isDirectory(pathFile)) {

                throw new ApiClientRunTimeException("Failed to login as root, you are not running " +
                                                        "on the Management Server");
            }
        }

        int port                  = portResolver.getPort(true);
        Process process           = invokeLoginAsRoot(pathFile, payload, port);
        String responseBodyString = UtilClass.getResponseFromProcess(process);
        String serverIpAddress    = LOCAL_SERVER_IP;

        //Creating ApiResponse
        loginResponse = new ApiLoginResponse(serverIpAddress, OK_RESPONSE_CODE, port,
                                             (JSONObject)UtilClass.convertToJson(responseBodyString));

        return loginResponse;
    }

    /**
     * This method allows to login into the management server with Root permissions.
     * In order to use this method the application should be run directly on the Management Server
     * and to own super-user privileges.
     *
     * @param payload String representing a JSON object containing the login command's arguments.
     *
     * @return {@link ApiResponse} object
     *
     * @throws ApiClientRunTimeException if error occurs while invoking login as root
     */
    public ApiLoginResponse loginAsRoot( String payload) {

            JSONObject pay = (JSONObject)UtilClass.convertToJson(payload);
            return loginAsRoot(pay);
    }

    /**
     * This command sends a web-service API request to the management server.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param command The command name to be invoked.
     * @param payload String representing a JSON object containing the command's arguments.
     * @param handleAsyncTaskAsSync Determines the behavior when the API server exec responds with a "task-id".
     *                    If TRUE it periodically checks the status of the task
     *                     and will not return until the task is completed.
     *
     * @return {@link ApiResponse} containing the server's answer for the request.
     *
     * @throws ApiClientException if error occurs while connecting to the server
     */
    public ApiResponse apiCall(ApiLoginResponse loginResponse, String command, String payload,
                               boolean handleAsyncTaskAsSync) throws ApiClientException
    {
        ApiResponse res;                //Response result
        String data = payload;          //Parameters for the call
        HttpsURLConnection connection = null;
        URL url;

        if (loginResponse == null) {
            throw new ApiClientException("ERROR: login Response is null");
        }
        if (command == null || command.isEmpty()) {
            throw new ApiClientException("ERROR: 'command' arg is invalid");
        }
        try {
            try {
                // 1)  Establish Connection
                url = new URL(URL_PROTOCOL, loginResponse.getServerIP(), loginResponse.getPort(), CONTEXT + command);
                connection = establishConnection(loginResponse, command, url);
            }
            catch (Exception e) {
                throw new ApiClientException("ERROR: failed occurs while connecting to the server, check that the" +
                                                     " server is up and running. Exception message: " + e.getMessage());
            }

            // 2) Send request
            try (DataOutputStream output = new DataOutputStream(connection.getOutputStream())) {

                output.write(data.getBytes("UTF-8"));

                // 3) Get Response
                InputStream input;
                if (connection.getResponseCode() != OK_RESPONSE_CODE) {
                    //In case of error
                    input = connection.getErrorStream();
                }
                else {
                    input = connection.getInputStream();
                }

                //Creating ApiResponse
                StringBuilder response = readResponse(input);
                if (LOGIN_CMD.equals(command)) {
                    res = new ApiLoginResponse(loginResponse.getServerIP(), connection.getResponseCode(),
                                               loginResponse.getPort(), (JSONObject)UtilClass.convertToJson(response.toString()));

                    // 4) When the command is 'login', hiding the password so that it would not appear in the debug file.
                    data = changePasswordInData(data);
                }
                else {
                    res = new ApiResponse(connection.getResponseCode(),
                                          (JSONObject)UtilClass.convertToJson(response.toString()));
                }
            }
            catch (ApiClientRunTimeException | IOException e) {
                throw new ApiClientException("ERROR: Could not connect to API server, check 'api status' " +
                                                     "for more details. Error message: " + e.getMessage());
            }
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        // 5) Store the request and the response (for debug purpose)
        if (debugFile != null) {
            makeApiCallLog(data, url, res);
        }

        // 6) If we want to wait for the task to end, wait for it
        if (handleAsyncTaskAsSync && res.isSuccess() && !SHOW_TASK_COMMAND.equals(command)){
            if (res.getPayload().containsKey("task-id")) {
                res = handleAsyncTaskAsSync(loginResponse, res.getPayload().get("task-id").toString());
            }
            else if (res.getPayload().containsKey("tasks")) {
                res = handleAsyncTasksAsSync(loginResponse, (JSONArray) res.getPayload().get("tasks"));
            }
        }

        return res;
    }

    /**
     *  This command sends a web-service API request to the management server.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command..
     * @param command  The command name to be invoked.
     * @param payload  JSON object contains command's arguments.
     * @param handleAsyncTaskAsSync Determines the behavior when the API server responds with a "task-id".
     *                              by default, the function will periodically check the status of the task
     *                              and will not return until the task is completed.
     *
     * @return {@link ApiResponse} containing the server's answer for the request.
     *
     * @throws ApiClientException if error occurs while connecting to the server
     */
    public ApiResponse apiCall(ApiLoginResponse loginResponse,String command, JSONObject payload,
                                 boolean handleAsyncTaskAsSync) throws ApiClientException {

        //Converting to jason object
        if(payload == null){
            throw new ApiClientException("Error: payload is invalid");
        }

        String pay = payload.toString();
        return apiCall(loginResponse,command, pay, handleAsyncTaskAsSync);
    }

    /**
     * This command sends a web-service API request to the management server.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param command The command name to be invoked.
     * @param payload JSON object contains command's arguments.
     *
     * @return {@link ApiResponse} containing the server's answer for the request.
     *
     * @throws ApiClientException if error occurs while connecting to the server
     */
    public ApiResponse apiCall(ApiLoginResponse loginResponse,String command,
                               JSONObject payload) throws ApiClientException {

        if(payload == null){
            throw new ApiClientException("Error: payload is invalid");
        }

        //Converting to jason object
        String pay = payload.toString();
        return apiCall(loginResponse,command, pay, true);
    }

    /**
     * This command sends a web-service API request to the management server.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param command The command name to be invoked.
     * @param payload String representing a JSON object contains command's arguments.
     *
     * @return {@link ApiResponse} containing the server's answer for the request.
     *
     * @throws ApiClientException if error occurs while connecting to the server
     */
    public ApiResponse apiCall(ApiLoginResponse loginResponse,String command,
                               String payload) throws ApiClientException {

        return apiCall(loginResponse,command, payload, true);
    }

    /**
     * This method receives a command query and returns the response - a list of all the desired objects.
     * The method's purpose is to return a list with all of the desired objects, in contrast to the API's that return
     * a list of a limited number of objects.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param command Name of API command. This command should be an API that returns an array of objects
     * @param key The items that the function collects.
     * @param payload String representing a JSON object containing the command's arguments.
     *
     * @return {@link ApiResponse} that contain all the objects
     * @throws ApiClientException
     */
    public ApiResponse apiQuery(ApiLoginResponse loginResponse, String command, String key, String payload)
            throws ApiClientException{

        return apiQuery(loginResponse,command,key, (JSONObject)UtilClass.convertToJson(payload));
    }

    /**
     * This method receives a command query and returns the response - a list of all the desired objects.
     * The method's purpose is to return a list with all of the desired objects, in contrast to the API's that return
     *  a list of a limited number of objects.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param command Name of API command. This command should be an API that returns an array of objects
     * @param key The items that the function collects.
     * @param payload JSON object containing the command's arguments.
     *
     * @return {@link ApiResponse} that contain all the objects
     *
     * @throws ApiClientException if error occurs while preforming an API call
     */
    public ApiResponse apiQuery(ApiLoginResponse loginResponse, String command, String key, JSONObject payload)
                                    throws ApiClientException {

        boolean finished        = false;               // will become true after getting all the data
        JSONArray allObjects    = new JSONArray();     // Accumulate all the objects from all the API calls
        int iterations          = 0;                   // Number of times we've made an API call
        ApiResponse apiResponse = null;                // API call response object
        int limit = getLimitQuery();

        int receivedObjects;
        int totalObjects;
        JSONObject offsetPayload  = new JSONObject(payload);

        // Did we got all the objects?
        while (!finished) {
            // Make the API call, offset should be increased by limit with each iteration
            offsetPayload.remove("limit");
            offsetPayload.remove("offset");
            offsetPayload.put("limit",limit);
            offsetPayload.put("offset",iterations * limit);

            iterations++;

            apiResponse = apiCall(loginResponse,command, offsetPayload);

            if (apiResponse.isSuccess()) {

                // Total number of objects
                JSONObject responsePayload = apiResponse.getPayload();
                if(!responsePayload.containsKey(key) || !responsePayload.containsKey("total")){
                    throw new ApiClientException("Error: No items to collect, check your key value");
                }

                totalObjects = Integer.parseInt(responsePayload.get("total").toString());
                if(totalObjects == 0 ){
                    return apiResponse;
                }

                // Number of objects we got so far
                receivedObjects = Integer.parseInt(responsePayload.get("to").toString());
                // Add the new objects to all the objects

                allObjects.addAll((JSONArray) responsePayload.get(key));

                // Did we get all the objects that we're supposed to get
                if (receivedObjects == totalObjects) {
                    finished = true;
                }
            } else {
                return apiResponse;
            }
        }

        //Creating result list of all the objects
        apiResponse.getPayload().remove("from");
        apiResponse.getPayload().remove("to");

        //Replace the data from the last API call with the array of all objects.
        apiResponse.getPayload().put(key, allObjects);

        return apiResponse;
    }

    /**
     * This function logs out from the server.
     *
     * @param loginResponse The {@link ApiLoginResponse} the response of the login command.
     *
     * @return The {@link ApiResponse} of the logout call.
     *
     * @throws ApiClientException if error occurs while preforming an API call or while writing the data
     *                              in to the debug file.
     */
    public ApiResponse exit(ApiLoginResponse loginResponse) throws ApiClientException {

        ApiResponse response;

        if (loginResponse == null){
            throw new ApiClientRunTimeException("The login response is null");
        }
        response = apiCall(loginResponse,"logout", "{}");

        return response;
    }

    /**
     * When Management Server executes a time consuming command e.g: run-script, install-policy, publish,
     * server performs it asynchronously. In this case a tasks-ids is returned to the user.
     * show-task command is used to receive the progress status and the result of the executed command.
     *
     * This method calls "handleAsyncTaskAsSync" for each of the tasks identifier.
     * The function returns when the tasks (and its sub-tasks) are no longer in-progress.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param tasksIdsObjects The tasks identifiers.
     *
     * @return ApiResponse Result of show-task command
     *
     * @throws ApiClientException if error occurs while preforming an API call
     */
    public ApiResponse handleAsyncTasksAsSync(ApiLoginResponse loginResponse,JSONArray tasksIdsObjects) throws ApiClientException {

        JSONArray tasks = new JSONArray();
        for (Object taskIdObj : tasksIdsObjects) {

            String taskId = ((JSONObject) taskIdObj).get("task-id").toString();
            handleAsyncTaskAsSync(loginResponse, taskId);
            tasks.add(taskId);
        }

        ApiResponse taskResult = apiCall(loginResponse, SHOW_TASK_COMMAND, "{\"task-id\": " +  tasks.toJSONString() + ", " +
                    " \"details-level\": \"full\"}", false);

        if ( taskResult == null || !taskResult.isSuccess()) {
            throw new ApiClientException("ERROR: failed to handle asynchronous tasks as synchronous, tasks result " +
                                                 "is undefined");
        }
        //Check that the status of the tasks are not 'failed'
        checkTasksStatus(taskResult);

        return taskResult;
    }

    /**
     * When Management Server executes a time consuming command e.g: run-script, install-policy, publish,
     * server performs it asynchronously. In this case a task-id is returned to the user.
     * show-task command is used to receive the progress status and the result of the executed command.
     *
     * This method calls "show-task" in interval of {@link ApiClient#ASYNC_TASK_SLEEP_SECONDS} to check the
     * status of the executed task.
     * The function returns when the task (and its sub-tasks) are no longer in-progress.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param taskId The task identifier.
     *
     * @return ApiResponse Result of show-task command
     *
     * @throws ApiClientException if error occurs while preforming an API call
     */
    public ApiResponse handleAsyncTaskAsSync(ApiLoginResponse loginResponse,String taskId) throws ApiClientException {

        boolean taskComplete   = false;
        ApiResponse taskResult = null;
        int totalTasks;

        // As long as there is a task in progress
        while (!taskComplete) {

            //Check the status of the task
            taskResult = apiCall(loginResponse, SHOW_TASK_COMMAND, "{\"task-id\": " + "\"" + taskId + "\", " +
                                                                " \"details-level\": \"full\"}", false);
            if ( taskResult == null ) {
                throw new ApiClientException("ERROR: failed to handle asynchronous task as synchronous, task result " +
                                                     "is undefined");
            }

            //Counts the number of tasks that are not in-progress
            int completedTasks = countTaskNotInProgress(taskResult.getPayload());

            //Get the total number of tasks
            totalTasks = ((JSONArray) taskResult.getPayload().get("tasks")).size();

            //Are we done?
            if (completedTasks == totalTasks) {
                taskComplete = true;
            } else {
                try {
                    Thread.sleep(ASYNC_TASK_SLEEP_SECONDS * 1000);
                } catch (Exception e) {
                    throw new ApiClientException("ERROR: failed while 'sleep' function");
                }
            }
        }
        //Check that the status of the tasks are not 'failed'
        checkTasksStatus(taskResult);

        return taskResult;
    }

    /**
     * This function iterates over all the tasks in the given ApiResponse and checks if the status of either of them
     * is 'failed'. In that case the ApiResponse status will be changed to false.
     *
     * @param taskResult {@link ApiResponse} returned from 'show-task' command
     */
    private void checkTasksStatus(ApiResponse taskResult){

        // Go over all the tasks
        JSONArray tasks = (JSONArray)taskResult.getPayload().get("tasks");
        for (Object taskObject : tasks) {
            JSONObject task = (JSONObject) taskObject;
            if (task.get("status").equals("failed") || task.get("status").equals("partially succeeded")) {
                taskResult.setSuccess(false);
                break;
            }
        }
    }

    /**
     * This method saves the logs to a debug file, if it exist.
     *
     * @throws ApiClientException if error occurs while writing the data in to the debug file.
     */
    private void saveDataToDebugFile(JSONObject apiCall) throws ApiClientException {

        if (debugFile != null) {
            try (BufferedWriter writer = Files.newBufferedWriter(debugFile, StandardCharsets.UTF_8,
                                                                 StandardOpenOption.APPEND)) {
                long sizeFile = Files.size(debugFile);
                String data;
                if (sizeFile == 0) {
                    data = apiCall.toString();
                }
                else{
                    data = "," + apiCall.toString();
                }
                writer.write(data);

            } catch (IOException x) {
                throw new ApiClientException("Error: failed writing to the debugger file");
            }
        }
    }

    /**
     * Gets the fingerprint Manager.
     * If the {@link FingerprintManager} not initialize yet, the function initialize it with
     * the default file name: {@link ApiClient#DEFAULT_FINGERPRINT_FILE}
     *
     * @return fingerprint Manager.
     */
    public FingerprintManager getFingerprintManager() {

        return fingerprintManager;
    }

    /**
     * Gets CheckFingerprint.
     *
     * @return CheckFingerprint.
     */
    public boolean getServerCheckFingerprint() {
        return checkFingerprint;
    }

    /**
     * This method execute the login command.
     *
     * @param mgmtCliPath The path of the system environment and command.
     * @param payload JSON object contains login command's arguments.
     * @param port The port number on management server
     *
     * @return Process that created after executing the login command.
     *
     * @throws ApiClientRunTimeException if error occurs while executing the login command
     */

    private Process invokeLoginAsRoot(Path mgmtCliPath, JSONObject payload, int port) throws ApiClientRunTimeException {

        Process process;
        try {
            //Creating the command
            List<String> command = new ArrayList<>(Arrays.asList(mgmtCliPath.toString(), "login", "-r", "true", "-f",
                                                                 "json" ,"--port", String.valueOf(port)));

            //Adding the domain to the command if it exist
            Set<String> keys = payload.keySet();
            Iterator<String> keysIterator = keys.iterator();
            String key;

            while(keysIterator.hasNext()){
                key = keysIterator.next();
                command.add(key);
                command.add(payload.get(key).toString());
            }

            //Executing the command
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            //run the command
            process = processBuilder.start();
            process.waitFor();

        } catch (IOException | InterruptedException e) {
            throw new ApiClientRunTimeException("Failed to login as root, "+ e.getMessage());
        }
        return process;
    }

    /**
     * This function establish an HttpsURL Connection.
     *
     * @param loginResponse The {@link ApiLoginResponse} of the login command.
     * @param url  The url.
     * @param data The data of the request.
     *
     * @return {@link HttpsURLConnection}
     *
     * @throws Exception if error occurs while establishing connection with the server
     */
    private HttpsURLConnection establishConnection(ApiLoginResponse loginResponse,String data, URL url) throws Exception {

        // Determine which certificate are valid
        TrustManager[] trustCerts = new TrustManager[]{new FingerX509TrustManager(loginResponse.getServerIP(), loginResponse.getPort())};

        // Install the trustCerts trust manager
        SSLContext sc = SSLContext.getInstance(TRANSPORT_LAYER_SECURITY);
        sc.init(null, trustCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HttpsURLConnection connection;

        if(proxySettings.isProxyServerExist()){
            //connection throw proxy tunnel
            if(proxySettings.getUserName()!= null){
                Authenticator authenticator = new Authenticator() {

                    public PasswordAuthentication getPasswordAuthentication() {
                        return (new PasswordAuthentication(
                                proxySettings.getUserName(), proxySettings.getPassword().toCharArray()));
                    }
                };
                Authenticator.setDefault(authenticator);
            }
            InetSocketAddress proxyInet = new InetSocketAddress(proxySettings.getHost(), proxySettings.getPort());
            Proxy proxy = new Proxy(Proxy.Type.HTTP, proxyInet);
             connection = (HttpsURLConnection) url.openConnection(proxy);
        }
        else{
           connection = (HttpsURLConnection) url.openConnection();
        }
        // Add request header
        connection.setRequestMethod("POST");
        connection.setRequestProperty("User-Agent", USER_AGENT);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Content-Length", Integer.toString(data.length()));

        connection.setConnectTimeout(TIMEOUT_CONNECTION_SEC * 1000);
        connection.setReadTimeout(READ_CONNECTION_SEC * 1000);

        //In all API calls (except for login) the header containing the Check Point session-id is required.
        if (loginResponse.getSid() != null) {

            connection.setRequestProperty(SID_HEADER, loginResponse.getSid());
        }

        connection.setDoInput(true);
        connection.setDoOutput(true);

        return connection;
    }

    /**
     * Sets the debugger file.
     *
     * @param fileName The new debugger file name.
     */
    private void setDebugFile(String fileName) {

        if(fileName.isEmpty() ){
            throw new ApiClientRunTimeException("Error: file name is invalid");
        }

        Path pathFile = Paths.get(fileName);
        if (Files.exists(pathFile)){
            try {
                Files.delete(pathFile);
            }
            catch (IOException e) {
                throw new ApiClientRunTimeException("Couldn't delete file");
            }
        }

        try {
            Files.createFile(pathFile);
        } catch (IOException x) {
            throw new ApiClientRunTimeException("Error: failed creating the debugger file");
        }

        debugFile = pathFile;
    }

    /**
     * This function is for log purposes.
     * Creates a new log from the response and sends the data and url.
     * Store the new log to the api call list.
     *
     * @param data     The data of the request.
     * @param url      The url of the connection.
     * @param response The response.
     *
     * @throws ApiClientException if error occurs while creating the new log
     */
    private void makeApiCallLog(String data, URL url, ApiResponse response) throws ApiClientException {

        JSONParser parser = new JSONParser();
        try {

            //Creates new log
            String headers        = "{\"User-Agent\":" + "\"" + USER_AGENT + "\",\"Accept\":\"application/json\"" +
                                    ",\"Content-Type\":\"application/json\",\"Content-Length\":" +
                                    Integer.toString(data.length()) + "}";

            Object obj            = parser.parse(data);
            JSONObject jsonObject = (JSONObject) obj;
            String req            = "{\"url\":" + "\"" + url.toString() + "\"," + "\"payload\":"
                                    + jsonObject.toJSONString() + ",\"headers\":" + headers + "}";

            JSONObject res        = new JSONObject();
            res.put("data", response.getPayload());
            res.put("status",response.getStatusCode());

            obj                   = parser.parse(req);
            JSONObject request    = (JSONObject) obj;

            obj                   = parser.parse("{\"request\":" + request + " ,\"response\":" + res+" }");

            //Contains the log of the api call
            JSONObject apiCall = (JSONObject) obj;
            saveDataToDebugFile(apiCall);

        } catch (ParseException e) {
            throw new ApiClientException("ERROR: failed to store the logs of the api call, check the payload " +
                                         "is in JSON format.");
        }
    }

    /**
     * This function gets all the input stream and return it as a string builder.
     *
     * @param input Input stream from the connection.
     *
     * @return String buffer that contain the input stream info.
     *
     * @throws ApiClientException if error occurs while reading the response from the server
     */
    private StringBuilder readResponse(InputStream input) throws ApiClientException {

        BufferedReader rd      = new BufferedReader(new InputStreamReader(input));
        StringBuilder response = new StringBuilder();
        String line;

        // Gets the response
        try {
            while((line = rd.readLine()) != null){
                response.append(line);
            }
        } catch (IOException e) {
            throw new ApiClientException("ERROR: failed reading the response from the server");
        }

        return response;
    }

    /**
     * This function is for secure purpose (i.e so the password in the debug file will be "****" and not the real one)
     * receives a data and change the password
     *
     * @param data The data that we want to change the password.
     *
     * @return The data after the change.
     *
     * @throws ApiClientException if error occurs while parsing the data
     */
    private String changePasswordInData(String data) throws ApiClientException {

        Object obj;
        JSONObject jsonObject;

        try {
            JSONParser parser = new JSONParser();
            obj               = parser.parse(data);
            jsonObject        = (JSONObject) obj;

            jsonObject.remove("password");
            jsonObject.put("password", "****");

        } catch (ParseException e) {
            throw new ApiClientException("ERROR: failed while parsing");
        }

        return (jsonObject.toString());
    }

    /**
     * This function sets the limit.
     *
     * @param limitQuery The limit for api query paging
     */
    public void setLimitQuery(int limitQuery)
    {
        this.limitQuery = limitQuery;
    }

    /**
     * This function gets the limit number.
     *
     * @return Limit number.
     */
    public int getLimitQuery()
    {
        return limitQuery;
    }

    /**
     * This function sets the current port to given port number.
     *
     * @param port The port of Management Server. (null to initialize the port to the default port)
     */
    public void setPort(Integer port){
        portResolver.setPort(port);
    }

    /**
     * Return the number of the tasks that are not longer in progress.
     *
     * @param tasks contains a list of tasks.
     *
     * @return The number of tasks that are not in progress.
     */
    private static int countTaskNotInProgress(JSONObject tasks) {

        int count = 0;
        JSONArray tasksData = ((JSONArray) tasks.get("tasks"));

        for (Object task : tasksData) {

            if (!((JSONObject) task).get("status").toString().equals(IN_PROGRESS)) {
                count++;
            }
        }

        return count;
    }

    /**
     * Checks if the server's fingerprint, which is stored in the local fingerprint storage file, equals to the
     * fingerprint received in the current API call.
     *
     * If server's fingerprint is not found in the file, a {@link CertificateException} is thrown.
     * If the fingerprint is found in the file, the function extracts the server fingerprint from the
     * certificate and compares them.
     * if they are not equal {@link CertificateException} is thrown
     *
     * @param server IP address or name of the Check Point Management Server.
     * @param cert Server certificate.
     * @param port The port number on management server
     *
     * @throws CertificateException if the fingerprint in the certificate storage file and
     * the sever fingerprint are not identical.
     */
    private void compareFingerPrint(String server, int port, java.security.cert.X509Certificate cert)
            throws CertificateException, ApiClientException {

        try {
            //Reading fingerprint from file
            String fingerprintFile = fingerprintManager.getFingerprintFromFile(server, port);

            if (fingerprintFile == null) {
                throw new CertificateException("Host: '" + server + "' with port: " + port +
                                                       " does not exist in the fingerprint file");
            }

            //Get fingerprint from server's certificate
            String fingerprintServer = fingerprintManager.getThumbPrint(cert);

            if (!fingerprintFile.equalsIgnoreCase(fingerprintServer)) {
                throw new CertificateException("The fingerprint (of Host: '" + server + "' with port: " + port +
                                                       ") that appears in the fingerprint file is different than the" +
                                                       " fingerprint in the certificate");
            }

        } catch (NoSuchAlgorithmException e) {
            throw new ApiClientException("ERROR: No such algorithm ");
        }
    }

    /**
     * class that extend the X509ExtendedTrustManager class.
     * if the boolean value checkFingerprintValidity is true :
     * the new class check if the server fingerprint match the fingerprint of the file.
     * if it doesn't matches the class trows exception and the connection with the server will stop.
     * if it matches it approve the connection with the server
     * if the boolean value checkFingerprintValidity is false:
     * the function approve the connection without checking the fingerprint
     */
    private class FingerX509TrustManager extends X509ExtendedTrustManager {

        String serverIpAddress;
        int port;
        public FingerX509TrustManager(String serverIpAddress, int port) {
            this.serverIpAddress = serverIpAddress;
            this.port = port;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            throw new CertificateException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

            if(x509Certificates.length<1){
                throw new IllegalArgumentException("Problem occurred while trying communicate with the server");
            }

            if (ApiClient.this.checkFingerprint ) {
                try {
                    compareFingerPrint(serverIpAddress, port, x509Certificates[0]);
                } catch (ApiClientException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket)
                                        throws CertificateException {
            throw new CertificateException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket)
                                        throws CertificateException {

            if(x509Certificates.length<1){
                throw new IllegalArgumentException("Problem occurred while trying communicate with the server");
            }

            if (ApiClient.this.checkFingerprint) {
                try {
                    compareFingerPrint(serverIpAddress, port, x509Certificates[0]);
                } catch (ApiClientException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)
                                        throws CertificateException {
            throw new CertificateException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)
                                        throws CertificateException {
            if(x509Certificates.length<1){
                throw new IllegalArgumentException("Problem occurred while trying communicate with the server");
            }

            if (ApiClient.this.checkFingerprint) {
                try {
                    compareFingerPrint(serverIpAddress, port, x509Certificates[0]);
                } catch (ApiClientException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}





