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

import static com.checkpoint.mgmt_api.client.ApiClient.*;

/**
 * This class provides arguments for ApiClient configuration.
 * All the arguments are configured with their default values.
 *
 * As default the debug file wont be created, the checkFingerprint sets to True, and thr port sets to 443.
 */
public class ApiClientArgs {

    //The debug file holds the data of all the communication between this client and Check Point's Management Server.
    private String debugFile         = null ;
    private String fingerprintFile   = DEFAULT_FINGERPRINT_FILE;

    //If set to True validates server fingerprint
    private boolean checkFingerprint = true;
    //Port on management server
    private int port                 = DEFAULT_PORT;
    private boolean isUserEnteredPort;
    //If set to null the connection won't use proxy tunneling
    private String proxySetting;
    private String tlsVersion = TRANSPORT_LAYER_SECURITY;

    /**
     * Gets the debugFile.
     *
     * @return The debug file name
     */
    public String getDebugFile() {

        return debugFile;
    }

    /**
     * Gets the fingerprint file.
     * The fingerprint file is initialized to {@link ApiClient#DEFAULT_FINGERPRINT_FILE}.
     *
     * @return The Fingerprint file name
     */
    public String getFingerprintFile() {

        return fingerprintFile;
    }

    /**
     * Gets the CheckFingerprint
     *
     * @return The CheckFingerprint.
     */
    public boolean isCheckFingerprint() {

        return checkFingerprint;
    }

    /**
     * Gets the port
     *
     * @return The port.
     */
    public int getPort() {
        return port;
    }

    /**
     * Sets the checkFingerprint.
     *
     * @param checkFingerprint If set to True validates the server's fingerprint
     */
    public void setCheckFingerprint(boolean checkFingerprint) {

        this.checkFingerprint = checkFingerprint;
    }

    /**
     * Get the proxySetting
     *
     * @return the proxySetting
     */
    public String getProxySetting(){
        return proxySetting;
    }

    /**
     * Sets the fingerprint file
     *
     * @param fingerprintFile File name to storage the fingerprints
     */
    public void setFingerprintFile(String fingerprintFile) {

        if(fingerprintFile!= null && !fingerprintFile.isEmpty()) {
            this.fingerprintFile = fingerprintFile;
        }
    }

    /**
     * Sets the debug file.
     *
     * @param debugFile File name to storage the logs.
     */
    public void setDebugFile(String debugFile) {

        if(debugFile!=null && !debugFile.isEmpty()){
            this.debugFile = debugFile;
        }
    }

    /**
     * Sets the port.
     * If input set to null the port will set to default port
     *
     * @param port New port.
     */
    public void setPort(Integer port) {

        if (port == null){
            this.port = DEFAULT_PORT;
            this.isUserEnteredPort = false;
        }
        else {
            this.port = port;
            this.isUserEnteredPort = true;
        }
    }

    /**
     * Gets the userAskedPort
     *
     * @return true if user entered a certain port
     */
    public boolean isUserEnteredPort(){
        return isUserEnteredPort;
    }

    /**
     * Sets the proxy setting.
     *
     * @param proxySetting If set to null the connection won't use proxy tunneling
     */
    public void setProxySetting(String proxySetting){
        this.proxySetting = proxySetting;
    }

    public String getTlsVersion() {
        return tlsVersion;
    }

    public void setTlsVersion(String tlsVersion) {
        if(tlsVersion==null){
            this.tlsVersion = TRANSPORT_LAYER_SECURITY;
        }
        else {
            this.tlsVersion = tlsVersion;
        }
    }
}
