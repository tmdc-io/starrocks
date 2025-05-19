// Copyright 2021-present StarRocks, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package com.starrocks.dataos;

import com.starrocks.authentication.AuthenticationException;
import com.starrocks.authentication.AuthenticationProvider;
import com.starrocks.authentication.UserAuthenticationInfo;
import com.starrocks.mysql.MysqlPassword;
import com.starrocks.mysql.privilege.AuthPlugin;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.sql.ast.UserAuthOption;
import com.starrocks.sql.ast.UserIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HeimdallAuthenticationProvider implements authentication using DataOS Heimdall service.
 * 
 * <p>This class serves as a bridge between StarRocks' authentication system and DataOS Heimdall,
 * which is an external authentication and authorization service. It allows StarRocks to delegate
 * user authentication to Heimdall, enabling centralized identity management in DataOS environments.
 * 
 * <p>The authentication flow works as follows:
 * 1. When a user connects to StarRocks, this provider processes the authentication request
 * 2. The user's API key is extracted from the connection credentials
 * 3. The API key is validated against the Heimdall service via DataOSClient
 * 4. If valid, the user is authenticated and granted access to StarRocks
 * 
 * <p>This provider works in conjunction with HeimdallAccessController which handles
 * authorization checks for various operations after authentication is complete.
 */
public class HeimdallAuthenticationProvider
        implements AuthenticationProvider {
    private static final Logger LOG = LogManager.getLogger(HeimdallAuthenticationProvider.class);
    public static final String PLUGIN_NAME = AuthPlugin.HEIMDALL.name();

    /**
     * Analyzes user authentication options and creates authentication info for a user.
     * 
     * <p>This method is called during user creation or when changing authentication.
     * For Heimdall authentication, we don't store passwords in StarRocks since
     * authentication is delegated to the Heimdall service.
     * 
     * @param userIdentity The user identity information (username, host)
     * @param userAuthOption Authentication options specified in CREATE/ALTER USER statement
     * @return UserAuthenticationInfo object containing authentication details
     * @throws AuthenticationException If there's an error in authentication option analysis
     */
    @Override
    public UserAuthenticationInfo analyzeAuthOption(UserIdentity userIdentity, UserAuthOption userAuthOption)
            throws AuthenticationException {
        UserAuthenticationInfo info = new UserAuthenticationInfo();
        info.setAuthPlugin(PLUGIN_NAME);
        info.setPassword(MysqlPassword.EMPTY_PASSWORD);  // No password stored locally
        info.setOrigUserHost(userIdentity.getUser(), userIdentity.getHost());
        info.setTextForAuthPlugin(userAuthOption.getAuthString());
        return info;
    }

    /**
     * Authenticates a user with credentials against Heimdall service.
     * 
     * <p>This method is called when a user attempts to connect to StarRocks.
     * It extracts the API key from the connection credentials and validates
     * it against the Heimdall service via DataOSClient.
     * 
     * <p>The authentication process for Heimdall:
     * 1. Extract the API key from the password bytes
     * 2. Call DataOSClient.authorize() to verify the API key with Heimdall
     * 3. If authorization succeeds, the user is authenticated
     * 4. If authorization fails, an AuthenticationException is thrown
     * 
     * @param user Username attempting to authenticate
     * @param host Host from which the user is connecting
     * @param remotePassword Password/API key provided during connection
     * @param randomString Random string used in some authentication protocols (not used for Heimdall)
     * @param authenticationInfo User's authentication information
     * @throws AuthenticationException If authentication fails
     */
    @Override
    public void authenticate(String user, String host, byte[] remotePassword, byte[] randomString,
                             UserAuthenticationInfo authenticationInfo) throws AuthenticationException {
        // clear password terminate string
        byte[] clearPassword = remotePassword;
        if (remotePassword[remotePassword.length - 1] == 0) {
            clearPassword = Arrays.copyOf(remotePassword, remotePassword.length - 1);
        }
        String apikey = new String(clearPassword, StandardCharsets.UTF_8);
        GlobalStateMgr.getCurrentState().getDataOSClient().authorize(user, host, apikey);
    }
}
