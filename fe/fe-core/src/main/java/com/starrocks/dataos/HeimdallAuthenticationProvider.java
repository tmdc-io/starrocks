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

public class HeimdallAuthenticationProvider
        implements AuthenticationProvider {
    private static final Logger LOG = LogManager.getLogger(HeimdallAuthenticationProvider.class);
    public static final String PLUGIN_NAME = AuthPlugin.HEIMDALL.name();

    @Override
    public UserAuthenticationInfo analyzeAuthOption(UserIdentity userIdentity, UserAuthOption userAuthOption)
            throws AuthenticationException {
        UserAuthenticationInfo info = new UserAuthenticationInfo();
        info.setAuthPlugin(PLUGIN_NAME);
        info.setPassword(MysqlPassword.EMPTY_PASSWORD);
        info.setOrigUserHost(userIdentity.getUser(), userIdentity.getHost());
        info.setTextForAuthPlugin(userAuthOption.getAuthString());
        return info;
    }

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
