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

/**
 * This Class is responsible for parsing the proxy settings string which was entered by a user.
 */
class ApiProxySettingsProcessor {

    //The user name in proxy server, optional
    private String  userName;

    //The password in proxy server, optional
    private String  password;

    //The host name/number of the proxy server, mandatory
    private String host;

    //The port name/number of the proxy server, optional
    private int port;

    //True if the connection need to pass via proxy server
    private boolean proxyServerExist;

    /**
     * Constructor
     *
     * @param proxySetting string in format 'user:password@host:port'
     */
    ApiProxySettingsProcessor(String proxySetting){
        parseProxySetting(proxySetting);
    }

    /**
     * This function parses the string of the proxy setting and define the variables accordingly
     *
     * @param proxySetting in format 'user:password@host:port'
     */
    private void parseProxySetting(String proxySetting) throws ApiClientRunTimeException
    {
        //The proxy setting string is empty, there is noting to do
        if(proxySetting == null || proxySetting.isEmpty()){
            return;
        }

        String[] parse = proxySetting.split("@");
        int parseLength = parse.length;
        if (parseLength > 2 || parseLength < 1 ) {
            throw new ApiClientRunTimeException("Error : proxy setting format is invalid, the format should be as " +
                               " following user:password@host:port (only the 'host' is mandatory)");
        }

        String[] hostAndPort;

        //user/password exist
        if (parse.length == 2  ){

            if(!parse[0].isEmpty()){

                String[] userAndPassword = parse[0].split(":");
                int userAndPasswordLength = userAndPassword.length;

                if(userAndPasswordLength > 2){
                    //To many parameters
                    throw new ApiClientRunTimeException("Error : proxy setting format is invalid, the format should be" +
                                        " as following : user:password@host:port (only the 'host' is mandatory)");
                }
                else if(userAndPasswordLength == 2){
                    //user and password exist
                    password = userAndPassword[1];
                }

                userName = userAndPassword[0];
            }
            hostAndPort = parse[1].split(":");
        }
        //Only host(maybe port)
        else{
            hostAndPort = parse[0].split(":");
        }

        int hostAndPortLength = hostAndPort.length;
        if (hostAndPortLength > 2 || hostAndPortLength < 1) {
            throw new ApiClientRunTimeException("Error : proxy setting format is invalid, the format should be " +
                                      "as following : user:password@host:port (only the 'host' is mandatory)");
        }
        //must have host parameter
        host = hostAndPort[0];
        if (hostAndPortLength == 2) {
            //port exist
            port = Integer.parseInt(hostAndPort[1]);
        }
        proxyServerExist = true;
    }

    /**
     * Gets host of the proxy server
     *
     * @return host name
     */
    public String getHost()
    {
        return host;
    }

    /**
     * Gets password for the proxy server
     *
     * @return password
     */
    public String getPassword()
    {
        return password;
    }

    /**
     * Gets user name for the proxy server
     *
     * @return user name
     */
    public String getUserName()
    {
        return userName;
    }

    /**
     * Gets port number
     *
     * @return port of proxy server
     */
    public int getPort()
    {
        return port;
    }

    /**
     * Gets the ProxyServerExist
     *
     * @return true if the the proxy settings parse succeed, otherwise false.
     */
    public boolean isProxyServerExist(){
        return proxyServerExist;
    }
}
