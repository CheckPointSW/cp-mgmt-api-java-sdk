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

/**
 * This class represents response object, that contains data, status code and the errors
 * of a checkpoint server's response to an api-call that has been invoked.
 */
public class ApiResponse {

    private static final int OK_RESPONSE_CODE = 200;

    // the information ot the response
    final private JSONObject data;
    // errors if exist
    final private JSONArray errors;
    // warning if exist
    final private JSONArray warnings;
    // the status of the response
    final private int statusCode;
    //set to true if the statusCode is 200 (OK)
    private boolean success;
    // the message if there is problem
    final private String errorMessage;

    /**
     * Constructor
     *
     * @param statusCode HTTP status  code
     * @param responseBody The response body
     */
      ApiResponse(int statusCode, JSONObject responseBody) {

         data = responseBody;
         this.statusCode = statusCode;

        if (this.statusCode == OK_RESPONSE_CODE) {

            success      = true;
            warnings     = null;
            errorMessage = null;
            errors       = null;

        } else {
            //The message in case of error
            success = false;
            errorMessage = data.get("message").toString();

            //If there are warnings
            if(data.containsKey("warnings")){
                warnings = (JSONArray)data.get("warnings");
            }else{
                warnings = null;
            }
            //If there are errors
            if(data.containsKey("errors")){
                errors = (JSONArray)data.get("errors");
            }else{
                errors = null;
            }
        }
    }

    /**
     * Gets the success status.
     *
     * @return Boolean success;
     */
    public boolean isSuccess() {

        return success;
    }

    /**
     * Gets the errorMessage.
     *
     * @return String of error Message if exist in the response.
     */
    public String getErrorMessage(){

        return errorMessage;
    }

    /**
     *Gets the response's status code.
     *
     * @return Status code
     */
    public int getStatusCode(){

        return statusCode;
    }

    /**
     * This function return the payload of the response.
     *
     * @return {@link JSONObject} of data
     */
    public JSONObject getPayload(){

        return data;
    }

    /**
     * Gets the warnings
     *
     * @return The warnings in the response if they exist, otherwise null.
     */
    public JSONArray getWarnings(){
        return warnings;
    }

    /**
     * Gets the errors
     *
     * @return The errors in the response if they exist, otherwise null.
     */
    public JSONArray getErrors(){
        return errors;
    }

    /**
     * Sets the success status.
     * @param success True to change the response status to true.
     */
    void setSuccess(boolean success){
        this.success = success;
    }
}
