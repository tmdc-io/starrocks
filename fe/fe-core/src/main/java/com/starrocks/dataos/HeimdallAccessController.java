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

/**
 * HeimdallAccessController extends StarRocks' native authorization system to integrate
 * with DataOS Heimdall service for access control.
 * 
 * <p>This class provides a hybrid authorization approach:
 * 1. For internal StarRocks catalogs, it uses the built-in authorization system
 * 2. For external catalogs (e.g., those managed by DataOS), it delegates authorization
 *    decisions to the Heimdall service through DataOSClient
 * 
 * <p>It implements fine-grained access control including:
 * - Catalog-level permissions
 * - Database-level permissions
 * - Table-level permissions
 * - Column masking policies (data redaction)
 * - Row-level access policies (row filtering)
 * 
 * <p>This controller works in conjunction with HeimdallAuthenticationProvider which
 * handles the authentication aspect of the security model.
 */
public class HeimdallAccessController extends NativeAccessController {
    private static final Logger LOG = LogManager.getLogger(HeimdallAccessController.class);

    /**
     * Checks if a user has permission to perform an action on a catalog.
     * 
     * <p>First delegates to the native access control system, then for non-internal
     * catalogs, performs an additional check with the Heimdall service.
     * 
     * @param currentUser The user identity requesting access
     * @param roleIds Set of role IDs associated with the user
     * @param catalogName Name of the catalog to check permissions for
     * @param privilegeType Type of privilege being requested. For catalogs, this includes:
     *                     <ul>
     *                     <li>CREATE - Permission to create databases within the catalog</li>
     *                     <li>ALTER - Permission to modify catalog properties</li>
     *                     <li>DROP - Permission to drop the entire catalog</li>
     *                     <li>USAGE - Permission to access/use the catalog</li>
     *                     <li>ALL - All permissions on the catalog</li>
     *                     </ul>
     * @throws AccessDeniedException If the user doesn't have the required permission
     */
    @Override
    public void checkCatalogAction(UserIdentity currentUser, Set<Long> roleIds, String catalogName, PrivilegeType privilegeType)
            throws AccessDeniedException {
        super.checkCatalogAction(currentUser, roleIds, catalogName, privilegeType);

        // Not an internal catalog? Check with Heimdall
        if (!Objects.equals(catalogName, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            GlobalStateMgr.getCurrentState().getDataOSClient().checkCatalogAction(currentUser, catalogName, privilegeType);
        }
    }

    /**
     * Checks if a user has permission to perform an action on a database.
     * 
     * <p>First delegates to the native access control system, then for non-internal
     * catalogs, performs an additional check with the Heimdall service.
     * 
     * @param currentUser The user identity requesting access
     * @param roleIds Set of role IDs associated with the user
     * @param catalogName Name of the catalog containing the database
     * @param db Name of the database to check permissions for
     * @param type Type of privilege being requested. For databases, this includes:
     *            <ul>
     *            <li>CREATE - Permission to create tables, views, or other objects in the database</li>
     *            <li>ALTER - Permission to modify database properties</li>
     *            <li>DROP - Permission to drop the database</li>
     *            <li>SELECT - Permission to query tables in the database</li>
     *            <li>INSERT - Permission to insert data into tables in the database</li>
     *            <li>UPDATE - Permission to modify data in tables in the database</li>
     *            <li>DELETE - Permission to delete data from tables in the database</li>
     *            <li>ALL - All permissions on the database</li>
     *            </ul>
     * @throws AccessDeniedException If the user doesn't have the required permission
     */
    @Override
    public void checkDbAction(UserIdentity currentUser, Set<Long> roleIds, String catalogName, String db,
            PrivilegeType type) throws AccessDeniedException {
        super.checkDbAction(currentUser, roleIds, catalogName, db, type);

        // Not an internal catalog? Check with Heimdall
        if (!Objects.equals(catalogName, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            GlobalStateMgr.getCurrentState().getDataOSClient().checkDbAction(currentUser, catalogName, db, type);
        }
    }

    /**
     * Checks if a user has permission to perform an action on a table.
     * 
     * <p>First delegates to the native access control system, then for non-internal
     * catalogs, performs an additional check with the Heimdall service.
     * 
     * @param currentUser The user identity requesting access
     * @param roleIds Set of role IDs associated with the user
     * @param table Name of the table to check permissions for
     * @param privilegeType Type of privilege being requested. For tables, this includes:
     *                     <ul>
     *                     <li>SELECT - Permission to query data from the table</li>
     *                     <li>INSERT - Permission to add new rows to the table</li>
     *                     <li>UPDATE - Permission to modify existing data in the table</li>
     *                     <li>DELETE - Permission to remove rows from the table</li>
     *                     <li>ALTER - Permission to modify the table structure</li>
     *                     <li>DROP - Permission to drop the table</li>
     *                     <li>TRUNCATE - Permission to remove all data from the table</li>
     *                     <li>REFERENCES - Permission to create foreign keys referencing the table</li>
     *                     <li>ALL - All permissions on the table</li>
     *                     </ul>
     * @throws AccessDeniedException If the user doesn't have the required permission
     */
    @Override
    public void checkTableAction(UserIdentity currentUser, Set<Long> roleIds, TableName table, PrivilegeType privilegeType)
            throws AccessDeniedException {
        super.checkTableAction(currentUser, roleIds, table, privilegeType);

        String catalog = table.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : table.getCatalog();
        // Not an internal catalog? Check with Heimdall
        if (!Objects.equals(catalog, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            GlobalStateMgr.getCurrentState().getDataOSClient().checkTableAction(currentUser, table, privilegeType);
        }
    }

    /**
     * Retrieves column masking policies for a table's columns.
     * 
     * <p>Column masking policies allow for dynamic data redaction, where certain users
     * see masked or transformed values instead of the actual data (e.g., showing only
     * the last 4 digits of credit card numbers).
     * 
     * <p>For tables in non-internal catalogs, it delegates to Heimdall to get the
     * appropriate masking expressions for each column.
     * 
     * @param context The current connection context
     * @param tableName Name of the table containing the columns
     * @param columns List of columns to check for masking policies
     * @return Map of column names to masking expressions, or null if no masking is needed
     */
    @Override
    public Map<String, Expr> getColumnMaskingPolicy(ConnectContext context, TableName tableName, List<Column> columns) {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();

        // Not an internal catalog? Check with Heimdall
        if (!Objects.equals(catalog, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            return GlobalStateMgr.getCurrentState().getDataOSClient().getColumnMaskExprs(context, tableName, columns);
        }
        return null;
    }

    /**
     * Retrieves row-level access policy for a table.
     * 
     * <p>Row-level access policies filter the rows a user can see in a table based on
     * predefined conditions (e.g., a sales rep can only see customers in their region).
     * 
     * <p>For tables in non-internal catalogs, it delegates to Heimdall to get the
     * appropriate row filtering expression.
     * 
     * @param context The current connection context
     * @param tableName Name of the table to check for row access policies
     * @return Expression representing the row filtering condition, or null if no filtering is needed
     */
    @Override
    public Expr getRowAccessPolicy(ConnectContext context, TableName tableName) {
        String catalog = tableName.getCatalog() == null ? InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME : tableName.getCatalog();

        // Not an internal catalog? Check with Heimdall
        if (!Objects.equals(catalog, InternalCatalog.DEFAULT_INTERNAL_CATALOG_NAME)) {
            return GlobalStateMgr.getCurrentState().getDataOSClient().getRowFilterExpr(context, tableName);
        }
        return null;
    }

}
