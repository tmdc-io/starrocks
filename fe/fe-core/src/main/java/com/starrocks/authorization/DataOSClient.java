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

import com.starrocks.analysis.Expr;
import com.starrocks.analysis.TableName;
import com.starrocks.authentication.AuthenticationException;
import com.starrocks.catalog.Column;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.ast.UserIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;

public class DataOSClient {
    private static final Logger LOG = LogManager.getLogger(DataOSClient.class);

    // Use supplied apikey
    public void authorize(String user, String host, String apikey) throws AuthenticationException {
        LOG.info(">> Authorize >> user: {}, host: {}, apikey: {}", user, host, apikey);
    }

    // Use DATAOS_RUN_AS_APIKEY
    public boolean isAdmin(String user, String host) throws AuthenticationException {
        LOG.info(">> isAdmin >> user: {}, host: {}", user, host);
        return user.startsWith("animesh"); // Test condition!
    }

    public void checkTableAction(UserIdentity user, TableName table, PrivilegeType type)
            throws AccessDeniedException {
        String catalog = table.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : table.getCatalog();
        LOG.info(" >> checkTableAction >> user: {}, table: {}, type: {}",
                user, table, type);
    }

    public Map<String, Expr> getColumnMaskExprs(ConnectContext context, TableName table, List<Column> columns) {
        String catalog = table.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : table.getCatalog();
        UserIdentity userIdentity = context.getCurrentUserIdentity();
        LOG.info(">> getColumnMaskExprs user: {}, catalog: {}, table: {}, columns: {}",
                userIdentity, catalog, table, columns);

        return null;
    }

    public Expr getRowFilterExpr(ConnectContext context, TableName table) {
        String catalog = table.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : table.getCatalog();
        UserIdentity userIdentity = context.getCurrentUserIdentity();
        LOG.info(">> getRowFilterExpr user: {}, catalog: {}, table: {}",
                userIdentity, catalog, table);

        return null;
    }
}
