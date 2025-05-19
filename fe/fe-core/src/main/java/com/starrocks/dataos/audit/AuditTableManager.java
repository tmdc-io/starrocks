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

package com.starrocks.dataos.audit;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.starrocks.analysis.TableName;
import com.starrocks.analysis.TypeDef;
import com.starrocks.catalog.Database;
import com.starrocks.catalog.KeysType;
import com.starrocks.catalog.PrimitiveType;
import com.starrocks.catalog.ScalarType;
import com.starrocks.common.DdlException;
import com.starrocks.common.UserException;
import com.starrocks.common.util.FrontendDaemon;
import com.starrocks.qe.ConnectContext;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.sql.analyzer.Analyzer;
import com.starrocks.sql.ast.ColumnDef;
import com.starrocks.sql.ast.CreateDbStmt;
import com.starrocks.sql.ast.CreateTableStmt;
import com.starrocks.sql.ast.HashDistributionDesc;
import com.starrocks.sql.ast.KeysDesc;
import com.starrocks.sql.ast.RangePartitionDesc;
import com.starrocks.sql.common.EngineType;
import com.starrocks.statistic.StatisticUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * AuditTableManager is responsible for setting up and maintaining the audit database
 * and table infrastructure in StarRocks for query auditing.
 * <p>
 * This class performs the following functions:
 * 1. Creates the audit database (_audit_) if it doesn't exist
 * 2. Creates the audit table (query_log) with appropriate schema if it doesn't exist
 * 3. Defines the schema with all required columns for capturing query metrics
 * 4. Sets up partitioning (by timestamp) and distribution (by queryId)
 * 5. Provides column definitions and metadata for the audit table
 * <p>
 * The manager runs as a FrontendDaemon thread and automatically sets up the
 * infrastructure when the system starts up.
 */
public class AuditTableManager extends FrontendDaemon {
    private static final Logger LOG = LogManager.getLogger(AuditTableManager.class);

    public static final long SLEEP_TIME_SEC = 5; // Retry interval in seconds
    public static final String AUDIT_DB_NAME = "_audit_";
    public static final String AUDIT_TBL_NAME = "audit_log";

    private final AtomicBoolean isTableSetup = new AtomicBoolean(false);

    /**
     * Constructor initializes the daemon thread for the audit table manager
     */
    public AuditTableManager() {
        super("audit-table-manager");
    }

    /**
     * Main execution method that runs after the catalog is ready.
     * Ensures the audit database and table exist, creating them if necessary.
     */
    @Override
    protected void runAfterCatalogReady() {
        // To make UT pass, some UT will create database and table
        trySleep();
        while (!checkDatabaseExist()) { // DB exists?
            if (createDatabase()) {  // Create DB
                break;
            }
            trySleep();
        }

        // Table creation
        while (!checkTableExist()) {
            if (createTable()) {  // Create Table
                break;
            }
            trySleep();
        }

        // Stop
        LOG.info("Audit Table ({}.{}) management finished!", AUDIT_DB_NAME, AUDIT_TBL_NAME);
        this.isTableSetup.set(true);
        this.setStop();
    }

    /**
     * Returns whether the audit infrastructure is properly set up
     * @return true if the audit table is ready for use
     */
    public Boolean isTableSetup() {
        return isTableSetup.get();
    }

    /**
     * Utility method to sleep between retry attempts
     */
    private void trySleep() {
        try {
            Thread.sleep(SLEEP_TIME_SEC * 1000);
        } catch (InterruptedException e) {
            LOG.warn(e.getMessage(), e);
        }
    }

    /**
     * Checks if the audit database exists
     * @return true if the database exists
     */
    private boolean checkDatabaseExist() {
        return GlobalStateMgr.getCurrentState().getLocalMetastore().getDb(AUDIT_DB_NAME) != null;
    }

    /**
     * Creates the audit database
     * @return true if creation was successful
     */
    private boolean createDatabase() {
        CreateDbStmt dbStmt = new CreateDbStmt(false, AUDIT_DB_NAME);
        try {
            GlobalStateMgr.getCurrentState().getLocalMetastore().createDb(dbStmt.getFullDbName());
        } catch (UserException e) {
            LOG.warn("Failed to create database ", e);
            return false;
        }
        return checkDatabaseExist();
    }

    /**
     * Returns the qualified table name for the audit table
     * @return TableName object for the audit table
     */
    public TableName getAuditTableName() {
        return new TableName(AUDIT_DB_NAME, AUDIT_TBL_NAME);
    }

    /**
     * Returns the key column names for the audit table
     * @return List of key column names
     */
    public List<String> getAuditTableKeyColumnNames() {
        return ImmutableList.of(
                "query_id",
                "timestamp",
                "query_type"
        );
    }

    /**
     * Returns the partition column names for the audit table
     * @return List of partition column names
     */
    public List<String> getAuditTablePartitionColumnNames() {
        return ImmutableList.of(
                "timestamp"
        );
    }

    /**
     * Returns the distribution column names for the audit table
     * @return List of distribution column names
     */
    public List<String> getAuditTableDistributionColumnNames() {
        return ImmutableList.of(
                "query_id"
        );
    }

    /**
     * Returns all column names for the audit table
     * This defines the schema of the audit table
     * @return List of all column names
     */
    public List<String> getAuditTableColumnNames() {
        return ImmutableList.of(
                "query_id",
                "timestamp",
                "query_type",
                "client_ip",
                "user",
                "authorized_user",
                "resource_group",
                "catalog",
                "db",
                "state",
                "error_code",
                "query_time",
                "scan_bytes",
                "scan_rows",
                "return_rows",
                "cpu_cost_ns",
                "mem_cost_bytes",
                "stmt_id",
                "is_query",
                "is_big_query",
                "fe_ip",
                "stmt",
                "digest",
                "plan_cpu_costs",
                "plan_mem_costs",
                "pending_time_ms",
                "candidate_mvs",
                "hit_mvs",
                "warehouse"
        );
    }

    /**
     * Checks if the audit table exists
     * @return true if the table exists
     */
    private boolean checkTableExist() {
        Database db = GlobalStateMgr.getCurrentState().getLocalMetastore().getDb(AUDIT_DB_NAME);
        Preconditions.checkState(db != null);
        return GlobalStateMgr.getCurrentState().getLocalMetastore().getTable(db.getFullName(), AUDIT_TBL_NAME) != null;
    }

    /**
     * Creates a column definition with NULL allowed
     */
    private ColumnDef getColumnDefAllowNull(String name, TypeDef typeDef, String comment) {
        return new ColumnDef(name, typeDef, false, null, null,
                true, // Allow Null -> True
                ColumnDef.DefaultValueDef.NOT_SET, comment
        );
    }

    /**
     * Creates a column definition with NOT NULL constraint
     */
    private ColumnDef getColumnDefNotNull(String name, TypeDef typeDef, String comment) {
        return new ColumnDef(name, typeDef, false, null, null,
                false, // Allow Null -> False
                ColumnDef.DefaultValueDef.NOT_SET, comment
        );
    }

    /**
     * Creates the audit table with the appropriate schema and properties
     * <p>
     * The table is configured with:
     * - All required columns for query auditing
     * - Dynamic partitioning by day based on timestamp
     * - Distribution by queryId
     * - Duplicate key model for optimization
     *
     * @return true if table creation was successful
     * @see <a href="https://docs.starrocks.io/docs/administration/management/audit_loader/#verify-the-installation-and-query-audit-logs">...</a>
     */
    private boolean createTable() {
        // Define column types
        TypeDef text = new TypeDef(ScalarType.createVarcharType(1048576));
        TypeDef varchar512 = new TypeDef(ScalarType.createVarcharType(512));
        TypeDef varchar128 = new TypeDef(ScalarType.createVarcharType(128));
        TypeDef varchar96 = new TypeDef(ScalarType.createVarcharType(96));
        TypeDef varchar64 = new TypeDef(ScalarType.createVarcharType(64));
        TypeDef varchar32 = new TypeDef(ScalarType.createVarcharType(32));
        TypeDef varchar12 = new TypeDef(ScalarType.createVarcharType(12));
        TypeDef varchar8 = new TypeDef(ScalarType.createVarcharType(8));

        TypeDef dateTime = new TypeDef(ScalarType.createType(PrimitiveType.DATETIME));
        TypeDef bigint = new TypeDef(ScalarType.createType(PrimitiveType.BIGINT));
        TypeDef intType = new TypeDef(ScalarType.createType(PrimitiveType.INT));
        TypeDef tinyint = new TypeDef(ScalarType.createType(PrimitiveType.TINYINT));
        TypeDef dbl = new TypeDef(ScalarType.createType(PrimitiveType.DOUBLE));

        // Define columns with appropriate types and comments
        List<ColumnDef> columnDefs =  ImmutableList.of(
                getColumnDefNotNull("query_id", varchar64, "Unique query ID"),
                getColumnDefNotNull("timestamp", dateTime, "Query start time"),
                getColumnDefNotNull("query_type", varchar12, "Query type (query, slow_query, connection"),

                getColumnDefAllowNull("client_ip", varchar32, "Client IP address"),
                getColumnDefAllowNull("user", varchar64, "User who initiates the query"),
                getColumnDefAllowNull("authorized_user", varchar64, "user_identity"),
                getColumnDefAllowNull("resource_group", varchar64, "Resource group name"),
                getColumnDefAllowNull("catalog", varchar32, "Catalog name"),
                getColumnDefAllowNull("db", varchar96, "Database that the query scans"),
                getColumnDefAllowNull("state", varchar8, "Query state (EOF, ERR, OK)"),
                getColumnDefAllowNull("error_code", varchar512, "Error code"),
                getColumnDefAllowNull("query_time", bigint, "Query latency in milliseconds"),
                getColumnDefAllowNull("scan_bytes", bigint, "Size of the scanned data in bytes"),
                getColumnDefAllowNull("scan_rows", bigint, "Row count of the scanned data"),
                getColumnDefAllowNull("return_rows", bigint, "Row count of the result"),
                getColumnDefAllowNull("cpu_cost_ns", bigint, "CPU resources consumption time for query in nanoseconds"),
                getColumnDefAllowNull("mem_cost_bytes", bigint, "Memory cost for query in bytes"),
                getColumnDefAllowNull("stmt_id", intType, "Incremental SQL statement ID"),
                getColumnDefAllowNull("is_query", tinyint, "If the SQL is a query (0 and 1)"),
                getColumnDefAllowNull("is_big_query", tinyint, "If the SQL is a big query (0 and 1)"),
                getColumnDefAllowNull("fe_ip", varchar128, "IP address of FE that executes the SQL"),
                getColumnDefAllowNull("stmt", text, "Original SQL statement"),
                getColumnDefAllowNull("digest", varchar32, "Slow SQL fingerprint"),
                getColumnDefAllowNull("plan_cpu_costs", dbl, "CPU resources consumption time for planning in nanoseconds"),
                getColumnDefAllowNull("plan_mem_costs", dbl, "Memory cost for planning in bytes"),
                getColumnDefAllowNull("pending_time_ms", dbl,
                        "Time spent in pending state waiting for resources in milliseconds"),
                getColumnDefAllowNull("candidate_mvs", varchar512,
                        "List of candidate materialized views considered for the query"),
                getColumnDefAllowNull("hit_mvs", varchar512, "List of materialized views actually used for the query"),
                getColumnDefAllowNull("warehouse", varchar32, "Warehouse name used for the query execution")
        );

        // Configure table properties for dynamic partitioning
        Map<String, String> props = Maps.newHashMap();
        props.put("dynamic_partition.time_unit", "DAY");
        props.put("dynamic_partition.start", "-30");  // Keep 30 days of history
        props.put("dynamic_partition.end", "3");      // Prepare 3 days ahead
        props.put("dynamic_partition.prefix", "p");
        props.put("dynamic_partition.buckets", "3");
        props.put("dynamic_partition.enable", "true");
        props.put("replication_num", "3");

        try {
            // Create the table with appropriate settings
            CreateTableStmt stmt = new CreateTableStmt(
                    false,
                    false,
                    new TableName(AUDIT_DB_NAME, AUDIT_TBL_NAME),
                    columnDefs,
                    EngineType.defaultEngine().name(),
                    new KeysDesc(KeysType.DUP_KEYS, this.getAuditTableKeyColumnNames()),
                    new RangePartitionDesc(this.getAuditTablePartitionColumnNames(), null),
                    new HashDistributionDesc(3, this.getAuditTableDistributionColumnNames()),
                    props,
                    null,
                    "Audit log table");

            ConnectContext context = StatisticUtils.buildConnectContext();
            context.setDatabase(AUDIT_DB_NAME);
            
            // The Analyzer.analyze step is critical in the table creation process:
            // 1. Validates the CreateTableStmt for syntactic and semantic correctness
            // 2. Resolves all table schema references and type dependencies
            // 3. Performs authorization checks and validation against catalog rules
            // 4. Transforms the statement into an executable form with resolved references
            // 5. Sets up necessary metadata before actual table creation
            // Without this step, the raw statement would not be properly prepared for execution
            Analyzer.analyze(stmt, context);

            return GlobalStateMgr.getCurrentState().getLocalMetastore().createTable(stmt);
        } catch (DdlException e) {
            LOG.error("Error in creating query audit table ({}.{}), {}", AUDIT_DB_NAME, AUDIT_TBL_NAME, e);
        }

        return false;
    }
}
