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

// This file is based on code available under the Apache license here:
//   https://github.com/apache/incubator-doris/blob/master/fe/fe-core/src/main/java/org/apache/doris/qe/AuditLogBuilder.java

// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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

    public static final String AUDIT_DB_NAME = "_audit_";
    public static final String AUDIT_TBL_NAME = "audit_activities";
    public static final long SLEEP_TIME_SEC = 5; // 60s

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
        /*
         * CAUTION:
         *
         * 1. DO NOT change the table schema in the examples, or the log loading will fail.
         * 2. Because the fields of audit logs vary among different StarRocks versions, the new
         *   version AuditLoader collects the common fields among them from all available StarRocks versions.
         */
        List<ColumnDef> columnDefs =  ImmutableList.of(
                // queryId
                getColumnDefNotNull("queryId", new TypeDef(ScalarType.createVarcharType(64)),
                        "Unique query ID"),
                // timestamp
                getColumnDefNotNull("timestamp", new TypeDef(ScalarType.createType(PrimitiveType.DATETIME)),
                        "Query start time"),
                //queryType
                getColumnDefNotNull("queryType", new TypeDef(ScalarType.createVarcharType(12)),
                        "Query type (query, slow_query, connection"),

                // clientIp
                getColumnDefAllowNull("clientIp", new TypeDef(ScalarType.createVarcharType(32)),
                        "Client IP address"),
                // user
                getColumnDefAllowNull("user", new TypeDef(ScalarType.createVarcharType(64)),
                        "User who initiates the query"),
                // authorizedUser
                getColumnDefAllowNull("authorizedUser", new TypeDef(ScalarType.createVarcharType(64)),
                        "user_identity"),
                // resourceGroup
                getColumnDefAllowNull("resourceGroup", new TypeDef(ScalarType.createVarcharType(64)),
                        "Resource group name"),
                // catalog
                getColumnDefAllowNull("catalog", new TypeDef(ScalarType.createVarcharType(32)),
                        "Catalog name"),
                // db
                getColumnDefAllowNull("db", new TypeDef(ScalarType.createVarcharType(96)),
                        "Database that the query scans"),
                // state
                getColumnDefAllowNull("state", new TypeDef(ScalarType.createVarcharType(8)),
                        "Query state (EOF, ERR, OK)"),
                // errorCode
                getColumnDefAllowNull("errorCode", new TypeDef(ScalarType.createVarcharType(512)),
                        "Error code"),
                // queryTime
                getColumnDefAllowNull("queryTime", new TypeDef(ScalarType.createType(PrimitiveType.BIGINT)),
                        "Query latency in milliseconds"),
                // scanBytes
                getColumnDefAllowNull("scanBytes", new TypeDef(ScalarType.createType(PrimitiveType.BIGINT)),
                        "Size of the scanned data in bytes"),
                // scanRows
                getColumnDefAllowNull("scanRows", new TypeDef(ScalarType.createType(PrimitiveType.BIGINT)),
                        "Row count of the scanned data"),
                // returnRows
                getColumnDefAllowNull("returnRows", new TypeDef(ScalarType.createType(PrimitiveType.BIGINT)),
                        "Row count of the result"),
                // cpuCostNs
                getColumnDefAllowNull("cpuCostNs", new TypeDef(ScalarType.createType(PrimitiveType.BIGINT)),
                        "CPU resources consumption time for query in nanoseconds"),
                // memCostBytes
                getColumnDefAllowNull("memCostBytes", new TypeDef(ScalarType.createType(PrimitiveType.BIGINT)),
                        "Memory cost for query in bytes"),
                // stmtId
                getColumnDefAllowNull("stmtId", new TypeDef(ScalarType.createType(PrimitiveType.INT)),
                        "Incremental SQL statement ID"),
                // isQuery
                getColumnDefAllowNull("isQuery", new TypeDef(ScalarType.createType(PrimitiveType.TINYINT)),
                        "If the SQL is a query (0 and 1)"),
                // feIp
                getColumnDefAllowNull("feIp", new TypeDef(ScalarType.createVarcharType(128)),
                        "IP address of FE that executes the SQL"),
                // stmt
                getColumnDefAllowNull("stmt", new TypeDef(ScalarType.createVarcharType(1048576)),
                        "Original SQL statement"),
                // digest
                getColumnDefAllowNull("digest", new TypeDef(ScalarType.createVarcharType(32)),
                        "Slow SQL fingerprint"),
                // planCpuCosts
                getColumnDefAllowNull("planCpuCosts", new TypeDef(ScalarType.createType(PrimitiveType.DOUBLE)),
                        "CPU resources consumption time for planning in nanoseconds"),
                // planMemCosts
                getColumnDefAllowNull("planMemCosts", new TypeDef(ScalarType.createType(PrimitiveType.DOUBLE)),
                        "Memory cost for planning in bytes")
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
                    new KeysDesc(KeysType.DUP_KEYS, ImmutableList.of("queryId", "timestamp", "queryType")),
                    new RangePartitionDesc(ImmutableList.of("timestamp"), null),
                    new HashDistributionDesc(3, ImmutableList.of("queryId")),
                    props,
                    null,
                    "Audit log table");

            ConnectContext context = StatisticUtils.buildConnectContext();
            context.setDatabase(AUDIT_DB_NAME);
            Analyzer.analyze(stmt, context);

            return GlobalStateMgr.getCurrentState().getLocalMetastore().createTable(stmt);
        } catch (DdlException e) {
            LOG.error("Error in creating Audit Table ({}.{}), {}", AUDIT_DB_NAME, AUDIT_TBL_NAME, e);
        }

        return false;
    }
}
