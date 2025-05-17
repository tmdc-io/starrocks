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

import com.starrocks.common.util.DigitalVersion;
import com.starrocks.plugin.AuditEvent;
import com.starrocks.plugin.PluginInfo;
import com.starrocks.plugin.PluginMgr;
import com.starrocks.qe.AuditLogBuilder;
import com.starrocks.sql.ast.StatementBase;
import com.starrocks.sql.common.SqlDigestBuilder;
import com.starrocks.sql.parser.SqlParser;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class AuditTableLoaderPlugin extends AuditLogBuilder {
    private static final Logger LOG = LogManager.getLogger(AuditTableLoaderPlugin.class);

    private final PluginInfo pluginInfo;
    private static final SimpleDateFormat DATETIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private StringBuilder auditBuffer = new StringBuilder();
    private long lastLoadTime = 0;
    private BlockingQueue<AuditEvent> auditEventQueue;
    private AuditStreamLoader streamLoader;
    private Thread loadThread;

    private volatile boolean isClosed = false;
    private volatile boolean isInit = false;

    private boolean candidateMvsExists;
    private boolean hitMVsExists;

    private AuditTableManager auditTableManager;

    // Conf
    public int maxQueueSize = 1000;
    public int auditEventQueuePollInterval = 5;
    public int qeSlowLogMs = 5000;
    public int maxStmtLength = 1048576;
    public boolean enableComputeAllQueryDigest = false;

    public long maxBatchSize = 50 * 1024 * 1024;
    public long maxBatchIntervalSec = 60;

    public AuditTableLoaderPlugin() {
        pluginInfo = new PluginInfo(PluginMgr.BUILTIN_PLUGIN_PREFIX + "AuditTableBuilder", PluginInfo.PluginType.AUDIT,
                "builtin audit table loader", DigitalVersion.fromString("0.12.0"),
                DigitalVersion.fromString("1.8.31"), AuditLogBuilder.class.getName(), null, null);

        // Relevant Tables are created
        this.auditTableManager = new AuditTableManager();
        this.auditTableManager.start();

        this.lastLoadTime = System.currentTimeMillis();

        this.auditEventQueue = new LinkedBlockingQueue<>(maxQueueSize);
        this.streamLoader = new AuditStreamLoader();
        this.loadThread = new Thread(new LoadWorker(this.streamLoader), "audit-table-loader-thread");
        this.loadThread.start();

        this.candidateMvsExists = hasField(AuditEvent.class, "candidateMvs");
        this.hitMVsExists = hasField(AuditEvent.class, "hitMVs");

        this.isInit = true;
    }

    @Override
    public int flags() {
        return PLUGIN_INSTALL_EARLY;
    }

    @Override
    public void close() throws IOException {
        super.close();
        this.isClosed = true;
        if (this.loadThread != null) {
            try {
                this.loadThread.join(60000);
            } catch (InterruptedException e) {
                LOG.debug("encounter exception when closing the audit loader", e);
            }
        }
    }

    public PluginInfo getPluginInfo() {
        return pluginInfo;
    }

    @Override
    public void exec(AuditEvent event) {
        try {
            auditEventQueue.add(event);
        } catch (Exception e) {
            // In order to ensure that the system can run normally, here we directly
            // discard the current audit_event. If this problem occurs frequently,
            // improvement can be considered.
            LOG.warn("encounter exception when putting current audit batch, discard current audit event", e);
        }
    }

    private class LoadWorker implements Runnable {
        private AuditStreamLoader loader;

        public LoadWorker(AuditStreamLoader loader) {
            this.loader = loader;
        }

        public void run() {
            while (!isClosed) {
                try {
                    AuditEvent event = auditEventQueue.poll(auditEventQueuePollInterval, TimeUnit.SECONDS);
                    if (event != null) {
                        assembleAudit(event);
                    }
                    loadIfNecessary(this.loader);
                } catch (InterruptedException ie) {
                    LOG.debug("encounter exception when loading current audit batch", ie);
                } catch (Exception e) {
                    LOG.error("run audit logger error:", e);
                }
            }
        }
    }

    private void loadIfNecessary(AuditStreamLoader loader) {
        if (!this.auditTableManager.isTableSetup()) {
            LOG.info("*** Audit Table is not yet set *** ");
            return;
        }

        if (auditBuffer.length() < maxBatchSize && System.currentTimeMillis() - lastLoadTime < maxBatchIntervalSec * 1000) {
            return;
        }
        if (auditBuffer.length() == 0) {
            return;
        }

        lastLoadTime = System.currentTimeMillis();
        // begin to load
        try {
            AuditStreamLoader.LoadResponse response = loader.loadBatch(auditBuffer);
            LOG.debug("audit loader response: {}", response);
        } catch (Exception e) {
            LOG.error("encounter exception when putting current audit batch, discard current batch", e);
        } finally {
            // make a new string builder to receive following events.
            this.auditBuffer = new StringBuilder();
        }
    }

    public static synchronized String longToTimeString(long timeStamp) {
        if (timeStamp <= 0L) {
            return DATETIME_FORMAT.format(new Date());
        }
        return DATETIME_FORMAT.format(new Date(timeStamp));
    }

    private boolean hasField(Class<?> clazz, String fieldName) {
        Field[] fields = clazz.getDeclaredFields();
        for (Field field : fields) {
            if (field.getName().equals(fieldName)) {
                return true;
            }
        }
        return false;
    }

    private void assembleAudit(AuditEvent event) {
        String queryType = getQueryType(event);
        int isQuery = event.isQuery ? 1 : 0;
        // Compute digest for all queries
        if (enableComputeAllQueryDigest && (event.digest == null || StringUtils.isBlank(event.digest))) {
            event.digest = computeStatementDigest(event.stmt);
            LOG.debug("compute stmt digest, queryId: {} digest: {}", event.queryId, event.digest);
        }
        String candidateMvsVal = candidateMvsExists ? event.candidateMvs : "";
        String hitMVsVal = hitMVsExists ? event.hitMVs : "";
        String content = "{\"queryId\":\"" + getQueryId(queryType, event) + "\"," +
                "\"timestamp\":\"" + longToTimeString(event.timestamp) + "\"," +
                "\"queryType\":\"" + queryType + "\"," +
                "\"clientIp\":\"" + event.clientIp + "\"," +
                "\"user\":\"" + event.user + "\"," +
                "\"authorizedUser\":\"" + event.authorizedUser + "\"," +
                "\"resourceGroup\":\"" + event.resourceGroup + "\"," +
                "\"catalog\":\"" + event.catalog + "\"," +
                "\"db\":\"" + event.db + "\"," +
                "\"state\":\"" + event.state + "\"," +
                "\"errorCode\":\"" + event.errorCode + "\"," +
                "\"queryTime\":" + event.queryTime + "," +
                "\"scanBytes\":" + event.scanBytes + "," +
                "\"scanRows\":" + event.scanRows + "," +
                "\"returnRows\":" + event.returnRows + "," +
                "\"cpuCostNs\":" + event.cpuCostNs + "," +
                "\"memCostBytes\":" + event.memCostBytes + "," +
                "\"stmtId\":" + event.stmtId + "," +
                "\"isQuery\":" + isQuery + "," +
                "\"feIp\":\"" + event.feIp + "\"," +
                "\"stmt\":\"" + truncateByBytes(event.stmt) + "\"," +
                "\"digest\":\"" + event.digest + "\"," +
                "\"planCpuCosts\":" + event.planCpuCosts + "," +
                "\"planMemCosts\":" + event.planMemCosts + "," +
                "\"pendingTimeMs\":" + event.pendingTimeMs + "," +
                "\"candidateMVs\":\"" + candidateMvsVal + "\"," +
                "\"hitMvs\":\"" + hitMVsVal + "\"," +
                "\"warehouse\":\"" + event.warehouse + "\"}";
        if (auditBuffer.length() > 0) {
            auditBuffer.append(",");
        }
        auditBuffer.append(content);
    }

    private String getQueryId(String prefix, AuditEvent event) {
        return (Objects.isNull(event.queryId) || event.queryId.isEmpty()) ? prefix + "-" + UUID.randomUUID() : event.queryId;
    }

    private String getQueryType(AuditEvent event) {
        try {
            assert event != null;
            switch (event.type) {
                case CONNECTION:
                    return "connection";
                case DISCONNECTION:
                    return "disconnection";
                default:
                    return (event.queryTime > qeSlowLogMs) ? "slow_query" : "query";
            }
        } catch (Exception e) {
            return (event.queryTime > qeSlowLogMs) ? "slow_query" : "query";
        }
    }

    private String computeStatementDigest(String stmt) {
        List<StatementBase> stmts = SqlParser.parse(stmt, 32);
        StatementBase queryStmt = stmts.get(stmts.size() - 1);

        if (queryStmt == null) {
            return "";
        }
        String digest = SqlDigestBuilder.build(queryStmt);
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(digest.getBytes());
            return Hex.encodeHexString(md.digest());
        } catch (NoSuchAlgorithmException | NullPointerException e) {
            return "";
        }
    }

    private String truncateByBytes(String str) {
        int maxLen = Math.min(maxStmtLength, str.getBytes().length);
        if (maxLen >= str.getBytes().length) {
            return str;
        }
        Charset utf8Charset = StandardCharsets.UTF_8;
        CharsetDecoder decoder = utf8Charset.newDecoder();
        byte[] sb = str.getBytes();
        ByteBuffer buffer = ByteBuffer.wrap(sb, 0, maxLen);
        CharBuffer charBuffer = CharBuffer.allocate(maxLen);
        decoder.onMalformedInput(CodingErrorAction.IGNORE);
        decoder.decode(buffer, charBuffer, true);
        decoder.flush(charBuffer);
        return new String(charBuffer.array(), 0, charBuffer.position());
    }
}

