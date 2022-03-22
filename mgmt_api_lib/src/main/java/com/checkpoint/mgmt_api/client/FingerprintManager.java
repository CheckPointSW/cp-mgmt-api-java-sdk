/**
 * Copyright © 2016 Check Point Software Technologies Ltd.  All Rights Reserved.
 * Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee and without a signed licensing agreement, is hereby
 * granted, provided that the above copyright notice, this paragraph and the following three paragraphs appear in all copies, modifications, and distributions.
 * <p/>
 * CHECK POINT DOES NOT PROVIDE, AND HAS NO OBLIGATION TO PROVIDE, MAINTENANCE SERVICES, TECHNICAL OR CUSTOMER SUPPORT, UPDATES,
 * ENHANCEMENTS, OR MODIFICATIONS FOR THE SOFTWARE OR THE DOCUMENTATION.
 * <p/>
 * TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE SOFTWARE AND DOCUMENTATION IS PROVIDED ON AN "AS IS," "AS AVAILABLE" AND "WHERE-IS"
 * BASIS.  ALL CONDITIONS, REPRESENTATIONS AND WARRANTIES WITH RESPECT TO THE SOFTWARE OR ITS DOCUMENTATION, WHETHER EXPRESS, IMPLIED, STATUTORY
 * OR OTHERWISE, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT OF THIRD PARTY
 * RIGHTS, ARE HEREBY DISCLAIMED.
 * <p/>
 * IN NO EVENT SHALL CHECK POINT BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS,
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF CHECK POINT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.checkpoint.mgmt_api.client;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static com.checkpoint.mgmt_api.client.ApiClient.*;

/**
 * Summary of the principal methods:
 *
 * (1) getServerFingerprint       - Returns the server fingerprint.
 * (2) getFingerprintFromFile     - Returns the server fingerprint which is saved in the local fingerprint file.
 * (3) checkFingerprintValidity   - Returns true if the fingerprint from the file equals to the server fingerprint,
 * otherwise false.
 * (4) saveFingerprintToFile      - saves the server fingerprint to the local fingerprint file.
 * (5) deleteFingerprintFromFile  - delete a given server from the fingerprint file.
 */
public class FingerprintManager
{

    private static final String CRYPTOGRAPHIC_HASH = "SHA-256";
    public static final String FINGERPRINT_KEY = "fingerprint-sha256";

    private Path fingerprintFile;

    private final ReentrantReadWriteLock LOCK = new ReentrantReadWriteLock();

    //The setting for tunneling through proxy
    private ApiProxySettingsProcessor proxySettings;

    /**
     * Constructor
     *
     * @param path          The fingerprint file name.
     * @param proxySettings The proxy setting [user,password,server,port]
     * @throws ApiClientRunTimeException
     */
    FingerprintManager(String path, ApiProxySettingsProcessor proxySettings) throws ApiClientRunTimeException
    {

        setFingerprintFile(path);
        this.proxySettings = proxySettings;
    }

    /**
     * This function initiates HTTPS connection to the server and extracts the SHA256
     * fingerprint from the server's certificate.
     * The port set to default value: {@link ApiClient#DEFAULT_PORT}
     *
     * @param server The IP address or name of the Check Point Management Server
     * @return The SHA256 fingerprint.
     * @throws ApiClientException if an error occurs while connecting to the server.
     */
    public String getServerFingerprint(String server) throws ApiClientException
    {
        return getServerFingerprint(server, ApiClient.DEFAULT_PORT);
    }

    /**
     * This function initiates HTTPS connection to the server and extracts the SHA256
     * fingerprint from the server's certificate.
     *
     * @param server The IP address or name of the Check Point Management Server.
     * @param port   The port number on management server
     * @return The SHA256 fingerprint.
     * @throws ApiClientException if an error occurs while connecting to the server.
     */
    public String getServerFingerprint(String server, int port) throws ApiClientException
    {

        String fingerprint;
        HttpsURLConnection connection = null;

        if (server == null || server.isEmpty()) {
            throw new ApiClientException("ERROR: illegal server IP address: " + server);
        }

        try {
            try {
                connection = establishConnection(server, port);
            }
            catch (Exception e) {
                throw new ApiClientException("ERROR: failed establish connection, check the connection to the server");
            }

            //Send request
            try (DataOutputStream ignored = new DataOutputStream(connection.getOutputStream())) {
                //Connection was established to receive server's certificate. Skipping the payload.
            }
            catch (IOException e) {
                throw new ApiClientException("ERROR: failed connecting to the server: " + server);
            }

            try {
                fingerprint = getThumbPrint((X509Certificate) connection.getServerCertificates()[0]);
            }
            catch (Exception e) {
                throw new ApiClientException("ERROR: failed get the fingerprint from the server: " + server);
            }
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return fingerprint;
    }

    /**
     * Returns the server's fingerprint from a local fingerprints file.
     *
     * @param server The IP address or name of the Check Point Management Server.
     * @return The server's fingerprint from the file if exists, else return null.
     * @throws ApiClientException if error occurs while reading from the local fingerprint file
     */
    public String getFingerprintFromFile(String server) throws ApiClientException
    {
        return getFingerprintFromFile(server, ApiClient.DEFAULT_PORT);
    }


    /**
     * Returns the server's fingerprint from a local fingerprints file.
     *
     * @param server The IP address or name of the Check Point Management Server.
     * @param port   The port number on management server
     * @return The server's fingerprint from the file if exists, else return null.
     * @throws ApiClientException if error occurs while reading from the local fingerprint file
     */
    public String getFingerprintFromFile(String server, int port) throws ApiClientException
    {

        JSONParser parser = new JSONParser();

        String serverAndPort = buildStringToFingerprintFile(server, port);
        LOCK.readLock().lock();
        try (BufferedReader file = Files.newBufferedReader(fingerprintFile, StandardCharsets.UTF_8)) {

            JSONObject jsonObject = (JSONObject) parser.parse(file);

            if (jsonObject.containsKey(serverAndPort)) {

                return jsonObject.get(serverAndPort).toString();
            }
        }
        catch (Exception e) {
            throw new ApiClientException("Error: failed to get the fingerprint from the local fingerprint file");
        }
        finally {
            LOCK.readLock().unlock();
        }

        return null;
    }

    /**
     * This function checks if the server's fingerprints which is stored in the local fingerprints file
     * is equal to the server's fingerprint that is extracted from the server certificate.
     *
     * @param server IP address or name of the Check Point Management Server.
     * @return True if the server's fingerprints from the file equals to the one extracted from the certificate,
     * otherwise False.
     * @throws ApiClientException if error occurs while reading from the local fingerprint file, or will
     *                            connecting to the server.
     */
    public boolean checkFingerprintValidity(String server) throws ApiClientException
    {

        return checkFingerprintValidity(server, ApiClient.DEFAULT_PORT);
    }

    /**
     * This function checks if the server's fingerprints which is stored in the local fingerprints file
     * is equal to the server's fingerprint that is extracted from the server certificate.
     *
     * @param server IP address or name of the Check Point Management Server.
     * @param port   The port number on management server
     * @return True if the server's fingerprints from the file equals to the one extracted from the certificate,
     * otherwise False.
     * @throws ApiClientException if error occurs while reading from the local fingerprint file, or will
     *                            connecting to the server.
     */
    public boolean checkFingerprintValidity(String server, int port) throws ApiClientException
    {

        //Read the fingerprint from the local file
        String fingerprint = getFingerprintFromFile(server, port);

        if (fingerprint == null) {
            return false;
        }

        if (server != null && !server.isEmpty()) {
            String fingerprintServer = getServerFingerprint(server, port);
            return fingerprint.equalsIgnoreCase(fingerprintServer);
        }

        return false;
    }

    /**
     * This function stores server's fingerprint into a local file.
     * If server's IP address was already stored in the local file its fingerprint is updated.
     *
     * @param server      IP address or name of the Check Point Management Server
     * @param fingerprint A SHA256 fingerprint of the server's certificate.
     * @param port        The port number on management server
     * @throws ApiClientException if error occurs while reading or writing to the local fingerprint file.
     */

    public void saveFingerprintToFile(String server, String fingerprint, int port) throws ApiClientException
    {
        if (server == null || server.isEmpty() || fingerprint == null || fingerprint.isEmpty()) {
            throw new ApiClientException("Error: the server IP address or the fingerprint is invalid");
        }
        JSONParser parser = new JSONParser();

        LOCK.writeLock().lock();
        try (BufferedReader reader = Files.newBufferedReader(fingerprintFile, Charset.forName("UTF-8"))) {

            JSONObject jsonObject = (JSONObject) parser.parse(reader);

            //If server's IP address doesn't exist in the file or the fingerprint that was stored
            // doesn't match to the new one, then update it
            String serverAndPort = buildStringToFingerprintFile(server, port);
            if (!jsonObject.containsKey(serverAndPort) ||
                    !(jsonObject.get(serverAndPort).toString().equalsIgnoreCase(fingerprint))) {

                jsonObject.put(serverAndPort, fingerprint);
                //Write the update to the file
                writeToFile(jsonObject);
            }
        }
        catch (Exception e) {
            throw new ApiClientException("Error: failed to write fingerprint to the local fingerprint file");
        }
        finally {
            LOCK.writeLock().unlock();
        }
    }

    /**
     * This function stores server's fingerprint into a local file.
     * If server's IP address was already stored in the local file its fingerprint is updated.
     *
     * @param server      IP address or name of the Check Point Management Server
     * @param fingerprint A SHA256 fingerprint of the server's certificate.
     * @throws ApiClientException if error occurs while reading or writing to the local fingerprint file.
     */

    public void saveFingerprintToFile(String server, String fingerprint) throws ApiClientException
    {

        saveFingerprintToFile(server, fingerprint, ApiClient.DEFAULT_PORT);
    }

    /**
     * This function removes sever's fingerprint from the fingerprint file.
     * If server's IP address wasn't stored in the local file, the function doesn't do anything.
     *
     * @param server IP address or name of the Check Point Management Server.
     * @throws ApiClientException if error occurs while writing or reading from the local fingerprint file.
     */
    public void deleteFingerprintFromFile(String server) throws ApiClientException
    {
        deleteFingerprintFromFile(server, ApiClient.DEFAULT_PORT);
    }

    /**
     * This function removes sever's fingerprint from the fingerprint file.
     * If server's IP address wasn't stored in the local file, the function doesn't do anything.
     *
     * @param server IP address or name of the Check Point Management Server.
     * @param port   The port number on management server
     * @throws ApiClientException if error occurs while writing or reading from the local fingerprint file.
     */
    public void deleteFingerprintFromFile(String server, int port) throws ApiClientException
    {

        JSONParser parser = new JSONParser();
        String serverAndPort = buildStringToFingerprintFile(server, port);

        LOCK.writeLock().lock();
        try (BufferedReader reader = Files.newBufferedReader(fingerprintFile, StandardCharsets.UTF_8)) {

            JSONObject jsonObject = (JSONObject) parser.parse(reader);

            //If server exist in the file
            if (jsonObject.containsKey(serverAndPort)) {

                jsonObject.remove(serverAndPort);
                //Writes the update to the file
                writeToFile(jsonObject);
            }
        }
        catch (Exception e) {
            throw new ApiClientException("Error: failed to delete fingerprint from the local fingerprint file");
        }
        finally {

            LOCK.writeLock().unlock();
        }
    }

    /**
     * Gets the name of the fingerprints file.
     *
     * @return The name of the fingerprints file.
     */
    public String getFingerprintFileName()
    {

        return fingerprintFile.toString();
    }

    /**
     * This function extracts the fingerprint from a given certificate.
     *
     * @param certificate X509 certificate
     * @return The fingerprint of a giving certificate.
     * @throws NoSuchAlgorithmException if {@link FingerprintManager#CRYPTOGRAPHIC_HASH} is requested but is not available
     *                                  in the environment
     * @throws CertificateException     if error occurs while encoding the given certificate
     */
    String getThumbPrint(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateException
    {

        if (certificate == null) {
            throw new CertificateException("Error: The given certificate is invalid");
        }

        MessageDigest md = MessageDigest.getInstance(CRYPTOGRAPHIC_HASH);
        byte[] der = certificate.getEncoded();
        md.update(der);

        byte[] digest = md.digest();

        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    /**
     * This function writes a given {@link JSONObject} in to the local fingerprints file.
     *
     * @param jsonObject Json object.
     * @throws ApiClientException if error occurs while writing to the local fingerprint file.
     */
    private void writeToFile(JSONObject jsonObject) throws ApiClientException
    {

        if (jsonObject == null) {
            throw new ApiClientException("Error: jsonObject is invalid");
        }
        String data = jsonObject.toString();

        try (BufferedWriter writer = Files.newBufferedWriter(fingerprintFile, StandardCharsets.UTF_8)) {

            writer.write(data, 0, data.length());
        }
        catch (IOException e) {
            throw new ApiClientException("Error: failed creating the fingerprint file or writing to the local " +
                                                 "fingerprint file");
        }
    }

    /**
     * This function replaces the fingerprints file with a new fingerprint file
     * if file doesn't exists the function creates the file.
     *
     * @param fingerprintFile The name of the new fingerprint file.
     * @throws ApiClientRunTimeException if error occurs while creating or writing to the given fingerprint file.
     */
    private void setFingerprintFile(String fingerprintFile) throws ApiClientRunTimeException
    {

        if (fingerprintFile == null || fingerprintFile.isEmpty()) {
            throw new ApiClientRunTimeException("Error: file name is invalid");
        }

        Path pathFile = Paths.get(fingerprintFile);

        if (!Files.exists(pathFile)) {

            try (BufferedWriter writer = Files.newBufferedWriter(pathFile, StandardCharsets.UTF_8)) {

                String data = "{}";
                writer.write(data, 0, data.length());
            }
            catch (IOException e) {
                throw new ApiClientRunTimeException("Error: failed creating or writing to the file");
            }
        }
        this.fingerprintFile = pathFile;
    }

    /**
     * This function reads fingerprints of the management server from 'api fingerprint' command.
     * This function should be used only when running on the management server.
     *
     * @return {@link JSONArray} that contains json object of the fingerprints
     */
    public JSONArray getFingerprintFromApiFingerprintUtil()
    {

        Process process;

        try {
            //Executing the command
            ProcessBuilder processBuilder = new ProcessBuilder("api", "fingerprint", "-f", "json");
            processBuilder.redirectErrorStream(true);
            //run the command
            process = processBuilder.start();
            process.waitFor();
        }
        catch (IOException | InterruptedException e) {
            throw new ApiClientRunTimeException("Failed to get fingerprint from 'api fingerprint' command.\n" +
                                                        "Check that you are running on the Management Server. " +
                                                        "Error message:" + e.getMessage());
        }
        String responseBodyString = UtilClass.getResponseFromProcess(process);

        JSONArray result;
        try {
            result = (JSONArray) UtilClass.convertToJson(responseBodyString);
        }
        catch (ApiClientRunTimeException acrte) {
            // parsing 'api fingerprint -f json' response to json format failed
            try {
                //try to parse the response to text format (may occur on prier version to R80.10)

                String[] fingerprintApiSplit = responseBodyString.split("English");
                if (fingerprintApiSplit.length < 1) {
                    throw new ApiClientRunTimeException("Parsing 'api fingerprint' response failed.");
                }
                //get fingerprint value
                String[] fingerprintStringSplit = fingerprintApiSplit[0].split("=");
                if (fingerprintStringSplit.length < 2) {
                    throw new ApiClientRunTimeException("Parsing 'api fingerprint' response failed.");
                }
                String fingerprintValue = fingerprintStringSplit[1];
                String fingerprintValueInAsItInJsonFormat = fingerprintValue.replace(":", "");

                //create the result in json format
                JSONObject fingerprintObject = new JSONObject();
                fingerprintObject.put(FINGERPRINT_KEY, fingerprintValueInAsItInJsonFormat);
                result = new JSONArray();
                result.add(fingerprintObject);
            }
            catch (Exception e) {
                throw new ApiClientRunTimeException("Parsing 'api fingerprint' response failed. " +
                                                            "Result of 'api fingerprint' command: '"
                                                            + responseBodyString + "'");
            }
        }
        return result;
    }

    /**
     * This function build the string to be written to the fingerprint file
     *
     * @param server The IP address or name of the Check Point Management Server.
     * @param port   Port number
     * @return string with following format: {server + ":" + port}
     */
    private String buildStringToFingerprintFile(String server, int port)
    {
        return MessageFormat.format("{0}:{1}", server, port);
    }

    /**
     * This function establishes HTTPS connection.
     *
     * @param server The IP address or name of the Check Point Management Server.
     * @param port   The port number on management server
     * @return {@link HttpsURLConnection}
     * @throws Exception if error occurs while establishing connection with the server
     */
    private HttpsURLConnection establishConnection(String server, int port) throws Exception
    {

        //Build url
        URL url = new URL(URL_PROTOCOL, server, port, CONTEXT);

        //Trust all the certificates
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager()
        {
            @Override
            //sgignore next_line
            public java.security.cert.X509Certificate[] getAcceptedIssuers()
            {
                return null;
            }

            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) throws CertificateException
            {
                throw new CertificateException();
            }

            @Override
            //sgignore next_line
            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) throws CertificateException
            {
            }
        }};

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance(TRANSPORT_LAYER_SECURITY);
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HttpsURLConnection connection;
        if (proxySettings.isProxyServerExist()) {
            //connection throw proxy tunnel
            if (proxySettings.getUserName() != null) {

                Authenticator authenticator = new Authenticator()
                {

                    public PasswordAuthentication getPasswordAuthentication()
                    {
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
        else {
            connection = (HttpsURLConnection) url.openConnection();
        }

        //sgignore next_line
        connection.setHostnameVerifier(new HostnameVerifier()
        {
            @Override
            public boolean verify(String s, SSLSession sslSession)
            {
                return true;
            }
        });

        connection.setDoOutput(true);

        return connection;
    }
}
