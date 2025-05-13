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

import com.starrocks.analysis.Expr;
import com.starrocks.analysis.TableName;
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.NativeAccessController;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.Column;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.qe.ConnectContext;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.sql.ast.UserIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class HeimdallAccessController extends NativeAccessController {
    private static final Logger LOG = LogManager.getLogger(HeimdallAccessController.class);

    @Override
    public void checkTableAction(UserIdentity currentUser, Set<Long> roleIds, TableName tableName, PrivilegeType privilegeType)
            throws AccessDeniedException {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();
        LOG.info(" >> checkTableAction >> user: {}, table: {}, type: {}", currentUser, tableName, privilegeType);

        super.checkTableAction(currentUser, roleIds, tableName, privilegeType);

        // Note - This method should never be called unless the catalog of Iceberg type, and
        // this controller is explicitly enabled. But, no harm in double-checking
        if (!Objects.equals(catalog, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            GlobalStateMgr.getCurrentState().getDataOSClient().checkTableAction(currentUser, tableName, privilegeType);
        }
    }

    @Override
    public Map<String, Expr> getColumnMaskingPolicy(ConnectContext context, TableName tableName, List<Column> columns) {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();
        LOG.info(" >> getColumnMaskingPolicy >> user: {}, table: {}", context.getCurrentUserIdentity(), tableName);
        if (!Objects.equals(catalog, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            return GlobalStateMgr.getCurrentState().getDataOSClient().getColumnMaskExprs(context, tableName, columns);
        }
        return null;
    }

    @Override
    public Expr getRowAccessPolicy(ConnectContext context, TableName tableName) {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();
        LOG.info(" >> getRowAccessPolicy >> user: {}, table: {}", context.getCurrentUserIdentity(), tableName);
        if (!Objects.equals(catalog, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            return GlobalStateMgr.getCurrentState().getDataOSClient().getRowFilterExpr(context, tableName);
        }
        return null;
    }

}
