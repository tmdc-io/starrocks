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
import com.starrocks.authentication.AuthenticationException;
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.PrivilegeType;
import com.starrocks.catalog.Column;
import com.starrocks.catalog.InternalCatalog;
import com.starrocks.common.DdlException;
import com.starrocks.qe.ConnectContext;
import com.starrocks.sql.ast.UserIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DataOSClient {
    private static final Logger LOG = LogManager.getLogger(DataOSClient.class);

    /*
     * ====================
     * User related methods
     * ====================
     */

    // Use supplied apikey
    public void authorize(String user, String host, String apikey) throws AuthenticationException {
        LOG.info(">> Authorize >> user: {}, host: {}, apikey: {}", user, host, apikey);
    }

    // Use DATAOS_RUN_AS_APIKEY
    public boolean isAdmin(String user, String host) throws AuthenticationException {
        LOG.info(">> isAdmin >> user: {}, host: {}", user, host);
        return user.startsWith("animesh"); // Test condition!
    }

    // called before a new User tries to log-in
    public boolean userExists(String user) throws AuthenticationException {
        return true;
    }

    /*
     * ==============================
     * Depot & Secret related methods
     * ==============================
     */

    // Expects these keys in the map that is returned
    // "iceberg.catalog.type" = "rest",
    // "iceberg.catalog.uri" = "http://iceberg-rest:8181/",
    // "iceberg.catalog.warehouse" = "warehouse",
    // DATAOS_SECRET =
    // DATAOS_DEPOT_NAME
    public Map<String, String> resolveIcebergDepot(String depotAddress) throws DdlException {
        LOG.info(" >> resolveIcebergDepot >> depot: {}", depotAddress); // dataos://depot-name?purpose=hello

        Map<String, String> map = new HashMap<String, String>();
        map.put(Constants.DATAOS_DEPOT_NAME, depotAddress); // Should be depot-name, depot-resolver API returns it
        return map;
    }

    // Expects these keys in the map that is returned
    // com.starrocks.connector.share.credential.CloudConfigurationConstants.AWS_S3_ACCESS_KEY etc,
    public Map<String, String> resolveSecretForS3(String secret) throws DdlException {
        LOG.info(" >> resolveSecretForS3 >> secret: {}", secret);
        return null;
    }

    // Expects these keys in the map that is returned
    // com.starrocks.connector.share.credential.CloudConfigurationConstants.AWS_GLUE_ACCESS_KEY etc,
    public Map<String, String> resolveSecretForGlue(String secret) throws DdlException {
        LOG.info(" >> resolveSecretForGlue >> secret: {}", secret);
        return null;
    }

    // Expects these keys in the map that is returned
    // com.starrocks.connector.share.credential.CloudConfigurationConstants.AZURE_ADLS2_SHARED_KEY etc,
    public Map<String, String> resolveSecretForAzure(String secret) throws DdlException {
        LOG.info(" >> resolveSecretForAzure >> secret: {}", secret);
        return null;
    }

    // Expects these keys in the map that is returned
    // com.starrocks.connector.share.credential.CloudConfigurationConstants.GCP_GCS_SERVICE_ACCOUNT_PRIVATE_KEY etc,
    public Map<String, String> resolveSecretForGcp(String secret) throws DdlException {
        LOG.info(" >> resolveSecretForGcp >> secret: {}", secret);
        return null;
    }

    /*
     * ====================================
     * Data & Object Policy related methods
     * ====================================
     */

    public void checkCatalogAction(UserIdentity user, String catalog, PrivilegeType type)
            throws AccessDeniedException {
        LOG.info(" >> checkCatalogAction >> user: {}, catalog: {}, type: {}",
                user, catalog, type);
    }

    public void checkDbAction(UserIdentity user, String catalog, String db, PrivilegeType type)
            throws AccessDeniedException {
        LOG.info(" >> checkDbAction >> user: {}, catalog: {}, db: {}, type: {}",
                user, catalog, db, type);
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
