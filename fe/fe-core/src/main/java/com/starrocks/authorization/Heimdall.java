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
package com.starrocks.authorization;

import com.starrocks.authentication.AuthenticationException;
import com.starrocks.common.ErrorCode;
import com.starrocks.common.ErrorReportException;
import com.starrocks.sql.ast.UserIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Set;

public class Heimdall {
    private static final Logger LOG = LogManager.getLogger(Heimdall.class);

    public void authorize(String user, String host, String apikey) throws AuthenticationException {
        LOG.info(">> Authorize >> user: {}, host: {}, apikey: {}", user, host, apikey);
    }

    public void authorizeTable(UserIdentity userIdentity, Set<Long> roleIds, PrivilegeType privilegeType,
            ObjectType objectType, List<String> objectTokens) throws AccessDeniedException {
        LOG.info(" >> authorizeTable >> userIdentity: {}, roleIds: {}, privilegeType: {}, " +
                        "objectType: {}, objectTokens: {}",
                userIdentity, roleIds, privilegeType, objectType, objectTokens);

        // Now, check with Heimdall
        if (objectType == ObjectType.TABLE) {
            throw ErrorReportException.report(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                    privilegeType, objectType, "dataos://" + String.join("/", objectTokens));
        }

    }
}
