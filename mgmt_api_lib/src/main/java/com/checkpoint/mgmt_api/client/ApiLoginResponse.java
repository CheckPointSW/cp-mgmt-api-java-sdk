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

/**
 * This class represents response object, that contains data, status code, errors, session identifier, port number
 * and server IP address of a checkpoint server's response to an login command that has been invoked.
 */
public final class ApiLoginResponse extends ApiResponse{

    //Session-id.
    final private String sid;

    //Management server name or IP-address
    final private String serverIpAddress;
    final private String cloudMgmtId;

    //Port of connection
    final private int port;

    //Api version
    final private String apiVersion;

    public ApiLoginResponse(String serverIP, int statusCode, int port, JSONObject responseBody) {
        this(serverIP, statusCode, port, responseBody, null);
    }

    public ApiLoginResponse(String serverIP, int statusCode, int port, JSONObject responseBody, String cloudMgmtId) {

        super(statusCode,responseBody);

        this.serverIpAddress = serverIP;
        this.cloudMgmtId = cloudMgmtId;
        this.port            = port;

        if (getPayload().containsKey("sid")) {
            sid = getPayload().get("sid").toString();
        } else {
            sid = null;
        }

        if (getPayload().containsKey("api-server-version")){
            apiVersion = getPayload().get("api-server-version").toString();
        }
        else{
            apiVersion = null;
        }
    }

    /**
     * Gets the server IP address
     *
     * @return The server IP.
     */
    public String getServerIP(){
        return serverIpAddress;
    }

    /**
     * Gets the session identifier
     *
     * @return The sid
     */
    public String getSid(){
        return sid;
    }

    /**
     * Gets the port number
     *
     * @return The port
     */
    public int getPort()
    {
        return port;
    }

    /**
     * Gets the Api server version
     *
     * @return The version
     */
    public String getApiVersion(){return apiVersion;}

    /**
     * Gets the Smart-1 Cloud management UID
     *
     * @return The Smart-1 Cloud management UID
     */
    public String getCloudMgmtId() { return cloudMgmtId; }
}
