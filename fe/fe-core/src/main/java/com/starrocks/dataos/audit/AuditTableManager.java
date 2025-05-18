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

public class AuditTableManager extends FrontendDaemon {
    private static final Logger LOG = LogManager.getLogger(AuditTableManager.class);

    public static final long SLEEP_TIME_SEC = 5; // 60s
    public static final String AUDIT_DB_NAME = "_audit_";
    public static final String AUDIT_TBL_NAME = "query_log";

    private final AtomicBoolean isTableSetup = new AtomicBoolean(false);

    public AuditTableManager() {
        super("audit-table-manager");
    }

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

    public Boolean isTableSetup() {
        return isTableSetup.get();
    }

    private void trySleep() {
        try {
            Thread.sleep(SLEEP_TIME_SEC * 1000);
        } catch (InterruptedException e) {
            LOG.warn(e.getMessage(), e);
        }
    }

    private boolean checkDatabaseExist() {
        return GlobalStateMgr.getCurrentState().getLocalMetastore().getDb(AUDIT_DB_NAME) != null;
    }

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

    public TableName getAuditTableName() {
        return new TableName(AUDIT_DB_NAME, AUDIT_TBL_NAME);
    }

    public List<String> getAuditTableKeyColumnNames() {
        return ImmutableList.of(
                "queryId",
                "timestamp",
                "queryType"
        );
    }

    public List<String> getAuditTablePartitionColumnNames() {
        return ImmutableList.of(
                "timestamp"
        );
    }

    public List<String> getAuditTableDistributionColumnNames() {
        return ImmutableList.of(
                "queryId"
        );
    }

    public List<String> getAuditTableColumnNames() {
        return ImmutableList.of(
                "queryId",
                "timestamp",
                "queryType",
                "clientIp",
                "user",
                "authorizedUser",
                "resourceGroup",
                "catalog",
                "db",
                "state",
                "errorCode",
                "queryTime",
                "scanBytes",
                "scanRows",
                "returnRows",
                "cpuCostNs",
                "memCostBytes",
                "stmtId",
                "isQuery",
                "feIp",
                "stmt",
                "digest",
                "planCpuCosts",
                "planMemCosts"
        // ,"pendingTimeMs","candidateMVs","hitMvs"
        );
    }

    private boolean checkTableExist() {
        Database db = GlobalStateMgr.getCurrentState().getLocalMetastore().getDb(AUDIT_DB_NAME);
        Preconditions.checkState(db != null);
        return GlobalStateMgr.getCurrentState().getLocalMetastore().getTable(db.getFullName(), AUDIT_TBL_NAME) != null;
    }

    private ColumnDef getColumnDefAllowNull(String name, TypeDef typeDef, String comment) {
        return new ColumnDef(name, typeDef, false, null, null,
                true, // Allow Null -> True
                ColumnDef.DefaultValueDef.NOT_SET, comment
        );
    }

    private ColumnDef getColumnDefNotNull(String name, TypeDef typeDef, String comment) {
        return new ColumnDef(name, typeDef, false, null, null,
                false, // Allow Null -> False
                ColumnDef.DefaultValueDef.NOT_SET, comment
        );
    }

    // ref: https://docs.starrocks.io/docs/administration/management/audit_loader/#verify-the-installation-and-query-audit-logs
    private boolean createTable() {
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

        List<ColumnDef> columnDefs =  ImmutableList.of(
                getColumnDefNotNull("queryId", varchar64, "Unique query ID"),
                getColumnDefNotNull("timestamp", dateTime, "Query start time"),
                getColumnDefNotNull("queryType", varchar12, "Query type (query, slow_query, connection"),

                getColumnDefAllowNull("clientIp", varchar32, "Client IP address"),
                getColumnDefAllowNull("user", varchar64, "User who initiates the query"),
                getColumnDefAllowNull("authorizedUser", varchar64, "user_identity"),
                getColumnDefAllowNull("resourceGroup", varchar64, "Resource group name"),
                getColumnDefAllowNull("catalog", varchar32, "Catalog name"),
                getColumnDefAllowNull("db", varchar96, "Database that the query scans"),
                getColumnDefAllowNull("state", varchar8, "Query state (EOF, ERR, OK)"),
                getColumnDefAllowNull("errorCode", varchar512, "Error code"),
                getColumnDefAllowNull("queryTime", bigint, "Query latency in milliseconds"),
                getColumnDefAllowNull("scanBytes", bigint, "Size of the scanned data in bytes"),
                getColumnDefAllowNull("scanRows", bigint, "Row count of the scanned data"),
                getColumnDefAllowNull("returnRows", bigint, "Row count of the result"),
                getColumnDefAllowNull("cpuCostNs", bigint, "CPU resources consumption time for query in nanoseconds"),
                getColumnDefAllowNull("memCostBytes", bigint, "Memory cost for query in bytes"),
                getColumnDefAllowNull("stmtId", intType, "Incremental SQL statement ID"),
                getColumnDefAllowNull("isQuery", tinyint, "If the SQL is a query (0 and 1)"),
                getColumnDefAllowNull("feIp", varchar128, "IP address of FE that executes the SQL"),
                getColumnDefAllowNull("stmt", text, "Original SQL statement"),
                getColumnDefAllowNull("digest", varchar32, "Slow SQL fingerprint"),
                getColumnDefAllowNull("planCpuCosts", dbl, "CPU resources consumption time for planning in nanoseconds"),
                getColumnDefAllowNull("planMemCosts", dbl, "Memory cost for planning in bytes")
        );

        Map<String, String> props = Maps.newHashMap();
        props.put("dynamic_partition.time_unit", "DAY");
        props.put("dynamic_partition.start", "-30");
        props.put("dynamic_partition.end", "3");
        props.put("dynamic_partition.prefix", "p");
        props.put("dynamic_partition.buckets", "3");
        props.put("dynamic_partition.enable", "true");
        props.put("replication_num", "3");

        try {
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
                    "Query log table");

            ConnectContext context = StatisticUtils.buildConnectContext();
            context.setDatabase(AUDIT_DB_NAME);
            Analyzer.analyze(stmt, context);

            return GlobalStateMgr.getCurrentState().getLocalMetastore().createTable(stmt);
        } catch (DdlException e) {
            LOG.error("Error in creating query audit table ({}.{}), {}", AUDIT_DB_NAME, AUDIT_TBL_NAME, e);
        }

        return false;
    }
}
