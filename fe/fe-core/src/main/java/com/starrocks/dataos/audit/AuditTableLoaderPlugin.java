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

import com.starrocks.authentication.AuthenticationMgr;
import com.starrocks.common.Config;
import com.starrocks.common.util.DigitalVersion;
import com.starrocks.plugin.AuditEvent;
import com.starrocks.plugin.PluginInfo;
import com.starrocks.plugin.PluginMgr;
import com.starrocks.qe.AuditLogBuilder;
import com.starrocks.qe.SessionVariable;
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

/**
 * AuditTableLoaderPlugin is responsible for capturing and persisting query audit events
 * in StarRocks. It extends AuditLogBuilder to receive audit events and writes them to
 * a dedicated audit table (_audit_.query_log) via stream load.
 * <p>
 * The plugin handles:
 * 1. Receiving audit events (queries, slow queries, connections, etc.)
 * 2. Batching them for efficient loading
 * 3. Computing SQL digests for query fingerprinting
 * 4. Persisting audit data via stream load
 * <p>
 * This audit data can later be queried for monitoring, troubleshooting, and compliance purposes.
 */
public class AuditTableLoaderPlugin extends AuditLogBuilder {
    private static final Logger LOG = LogManager.getLogger(AuditTableLoaderPlugin.class);

    private final PluginInfo pluginInfo;
    private static final SimpleDateFormat DATETIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private StringBuilder auditBuffer = new StringBuilder();
    private long lastLoadTime = 0;
    private final BlockingQueue<AuditEvent> auditEventQueue;
    private final Thread loadThread;

    private final AuditTableManager auditTableManager;

    private volatile boolean isClosed = false;

    private final boolean candidateMvsExists;
    private final boolean hitMVsExists;

    // Configuration parameters
    public int maxQueueSize = 1000;                    // Maximum number of audit events in the queue
    public int auditEventQueuePollInterval = 5;        // Interval in seconds to poll the queue
    public int maxStmtLength = 1048576;                // Maximum length of SQL statements stored
    public boolean enableComputeAllQueryDigest = false; // Whether to compute digests for all queries

    public long maxBatchSize = 50 * 1024 * 1024;       // Maximum batch size in bytes
    public long maxBatchIntervalSec = 10;              // Maximum interval between batch loads

    /**
     * Constructor initializes the plugin with default settings and starts
     * the background thread for processing audit events.
     */
    public AuditTableLoaderPlugin() {
        pluginInfo = new PluginInfo(PluginMgr.BUILTIN_PLUGIN_PREFIX + "AuditTableLoaderPlugin",
                PluginInfo.PluginType.AUDIT,
                "builtin audit table loader",
                DigitalVersion.fromString("0.12.0"),
                DigitalVersion.fromString("1.8.31"),
                AuditTableLoaderPlugin.class.getName(),
                null,
                null);

        this.auditTableManager = new AuditTableManager();
        auditTableManager.start();

        this.lastLoadTime = System.currentTimeMillis();

        this.auditEventQueue = new LinkedBlockingQueue<>(maxQueueSize);
        AuditStreamLoader streamLoader = new AuditStreamLoader(
                "127.0.0.1:" + Config.http_port,
                AuthenticationMgr.ROOT_USER,
                Config.root_password,
                this.auditTableManager.getAuditTableColumnNames());
        this.loadThread = new Thread(new LoadWorker(streamLoader), "audit-table-loader-thread");
        this.loadThread.start();

        // Check if fields exist through reflection to support backward compatibility
        this.candidateMvsExists = hasField("candidateMvs");
        this.hitMVsExists = hasField("hitMVs");
    }

    /**
     * Specifies plugin installation flags that control initialization timing.
     * 
     * @return PLUGIN_INSTALL_EARLY flag which indicates this plugin should be loaded
     *         during an early phase of the system startup sequence
     */
    @Override
    public int flags() {
        // PLUGIN_INSTALL_EARLY ensures the audit plugin is initialized early in the startup sequence
        // This is critical for:
        // 1. Capturing all query events from the very beginning of the system's operation
        // 2. Setting up audit infrastructure before other components start generating events
        // 3. Ensuring complete audit coverage for compliance and security purposes
        return PLUGIN_INSTALL_EARLY;
    }

    /**
     * Filters which types of audit events this plugin should process.
     * <p>
     * This method acts as a gate that determines which events will be processed by the
     * exec() method and ultimately stored in the audit table. It currently accepts:
     * <p>
     * - AFTER_QUERY: Events generated after a query has completed execution, containing
     *   the full performance metrics, resource usage, and execution status.
     * <p>
     * - CONNECTION: Events related to client connections to the database, which are
     *   important for tracking user session activity and access patterns.
     * <p>
     * Other event types like BEFORE_QUERY (fired before execution) and DISCONNECTION
     * are filtered out as they either lack complete execution metrics or are less
     * relevant for audit purposes.
     * 
     * @param type The type of audit event to filter
     * @return true if the event should be processed, false if it should be ignored
     */
    @Override
    public boolean eventFilter(AuditEvent.EventType type) {
        return type == AuditEvent.EventType.AFTER_QUERY || type == AuditEvent.EventType.CONNECTION;
    }

    /**
     * Determines if an audit event represents a "big query" based on configured thresholds.
     * <p>
     * A query is considered "big" if it exceeds any of the following thresholds:
     * 1. CPU time threshold (in seconds, converted to nanoseconds for comparison)
     * 2. Data scan bytes threshold
     * 3. Number of rows scanned threshold
     * <p>
     * Users can control these thresholds via the following session or global variables:
     * - big_query_log_cpu_second_threshold: Default = 480 seconds (8 minutes)
     *   SET GLOBAL big_query_log_cpu_second_threshold = 600;  // Set to 10 minutes
     * <p>
     * - big_query_log_scan_bytes_threshold: Default = 10737418240 bytes (10 GB)
     *   SET GLOBAL big_query_log_scan_bytes_threshold = 21474836480;  // Set to 20 GB
     * <p>
     * - big_query_log_scan_rows_threshold: Default = 1500000000 rows
     *   SET GLOBAL big_query_log_scan_rows_threshold = 3000000000;  // Set to 3 billion rows
     * <p>
     * Additionally, big query logging must be enabled with:
     * SET GLOBAL enable_big_query_log = true;
     * <p>
     * Big queries are resource-intensive operations that may require special monitoring
     * or handling. This method is used to identify such queries for potential special
     * treatment in the logging system. Identified big queries are logged to 
     * fe/log/fe.big_query.log for analysis.
     * <p>
     * Thresholds of -1 indicate that the specific threshold check is disabled.
     * 
     * @param event The audit event to evaluate
     * @return true if the event represents a big query, false otherwise
     * @see com.starrocks.common.Config for default values
     */
    private boolean isBigQuery(AuditEvent event) {
        if (event.bigQueryLogCPUSecondThreshold >= 0 &&
                event.cpuCostNs > event.bigQueryLogCPUSecondThreshold * 1000000000L) {
            return true;
        }
        if (event.bigQueryLogScanBytesThreshold >= 0 && event.scanBytes > event.bigQueryLogScanBytesThreshold) {
            return true;
        }
        return event.bigQueryLogScanRowsThreshold >= 0 && event.scanRows > event.bigQueryLogScanRowsThreshold;
    }

    /**
     * Properly close resources when the plugin is unloaded
     */
    @Override
    public void close() throws IOException {
        super.close();
        this.isClosed = true;
        if (this.loadThread != null) {
            try {
                this.loadThread.join(AuditTableManager.SLEEP_TIME_SEC * 10000);
            } catch (InterruptedException e) {
                LOG.debug("Error in closing the audit loader", e);
            }
        }
    }

    public PluginInfo getPluginInfo() {
        return pluginInfo;
    }

    /**
     * Entry point for audit events. Receives events and places them in the queue
     * for asynchronous processing.
     * 
     * @param event The audit event to be processed
     */
    @Override
    public void exec(AuditEvent event) {
        try {
            LOG.info("AuditEvent: user = {}, isQuery = {}, query = {}", event.authorizedUser, event.isQuery, event.stmt);
            auditEventQueue.add(event);
        } catch (Exception e) {
            // In order to ensure that the system can run normally, here we directly
            // discard the current audit_event. If this problem occurs frequently,
            // improvement can be considered.
            LOG.warn("encounter exception when putting current audit batch, discard current audit event", e);
        }
    }

    /**
     * Worker thread that processes audit events from the queue and loads them into
     * the audit table when batch size or time thresholds are reached.
     */
    private class LoadWorker implements Runnable {
        private final AuditStreamLoader loader;

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

    /**
     * Determines if the current batch should be loaded into the audit table based on
     * size or time thresholds.
     * 
     * @param loader The stream loader for loading data
     */
    private void loadIfNecessary(AuditStreamLoader loader) {
        if (!this.auditTableManager.isTableSetup()) {
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
            AuditStreamLoader.LoadResponse response = loader.loadBatch(new StringBuilder(this.auditBuffer));
            LOG.info("Audit events loaded into {}, response: {}", this.auditTableManager.getAuditTableName(), response);
        } catch (Exception e) {
            LOG.error("Error in loading audit events, discard current batch", e);
        } finally {
            // make a new string builder to receive following events.
            this.auditBuffer = new StringBuilder();
        }
    }

    /**
     * Formats a timestamp as a datetime string
     */
    public static synchronized String longToTimeString(long timeStamp) {
        if (timeStamp <= 0L) {
            return DATETIME_FORMAT.format(new Date());
        }
        return DATETIME_FORMAT.format(new Date(timeStamp));
    }

    /**
     * Checks if a field exists in a class using reflection
     */
    private boolean hasField(String fieldName) {
        Field[] fields = AuditEvent.class.getDeclaredFields();
        for (Field field : fields) {
            if (field.getName().equals(fieldName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Assembles a JSON representation of an audit event and adds it to the buffer
     */
    private void assembleAudit(AuditEvent event) {
        String queryType = getQueryType(event);
        int isQuery = event.isQuery ? 1 : 0;
        int isBigQuery = isBigQuery(event) ? 1 : 0;
        // Compute digest for all queries
        if (enableComputeAllQueryDigest && (event.digest == null || StringUtils.isBlank(event.digest))) {
            event.digest = computeStatementDigest(event.stmt);
            LOG.debug("compute stmt digest, queryId: {} digest: {}", event.queryId, event.digest);
        }
        String candidateMvsVal = candidateMvsExists ? event.candidateMvs : "";
        String hitMVsVal = hitMVsExists ? event.hitMVs : "";
        String content = "{\"query_id\":\"" + getQueryId(queryType, event) + "\"," +
                "\"timestamp\":\"" + longToTimeString(event.timestamp) + "\"," +
                "\"query_type\":\"" + queryType + "\"," +
                "\"client_ip\":\"" + event.clientIp + "\"," +
                "\"user\":\"" + event.user + "\"," +
                "\"authorized_user\":\"" + event.authorizedUser + "\"," +
                "\"resource_group\":\"" + event.resourceGroup + "\"," +
                "\"catalog\":\"" + event.catalog + "\"," +
                "\"db\":\"" + event.db + "\"," +
                "\"state\":\"" + event.state + "\"," +
                "\"error_code\":\"" + event.errorCode + "\"," +
                "\"query_time\":" + event.queryTime + "," +
                "\"scan_bytes\":" + event.scanBytes + "," +
                "\"scan_rows\":" + event.scanRows + "," +
                "\"return_rows\":" + event.returnRows + "," +
                "\"cpu_cost_ns\":" + event.cpuCostNs + "," +
                "\"mem_cost_bytes\":" + event.memCostBytes + "," +
                "\"stmt_id\":" + event.stmtId + "," +
                "\"is_query\":" + isQuery + "," +
                "\"is_big_query\":" + isBigQuery + "," +
                "\"fe_ip\":\"" + event.feIp + "\"," +
                "\"stmt\":\"" + truncateByBytes(event.stmt) + "\"," +
                "\"digest\":\"" + event.digest + "\"," +
                "\"plan_cpu_costs\":" + event.planCpuCosts + "," +
                "\"plan_mem_costs\":" + event.planMemCosts + "," +
                "\"pending_time_ms\":" + event.pendingTimeMs + "," +
                "\"candidate_mvs\":\"" + candidateMvsVal + "\"," +
                "\"hit_mvs\":\"" + hitMVsVal + "\"," +
                "\"warehouse\":\"" + event.warehouse + "\"}";
        if (auditBuffer.length() > 0) {
            auditBuffer.append(",");
        }
        auditBuffer.append(content);
    }

    /**
     * Generates a query ID if one doesn't exist
     */
    private String getQueryId(String prefix, AuditEvent event) {
        return (Objects.isNull(event.queryId) || event.queryId.isEmpty()) ? prefix + "-" + UUID.randomUUID() : event.queryId;
    }

    /**
     * Determines the query type based on event type and duration
     */
    private String getQueryType(AuditEvent event) {
        try {
            assert event != null;
            switch (event.type) {
                case CONNECTION:
                    return "connection";
                case DISCONNECTION:
                    return "disconnection";
                default:
                    return isSlowQuery(event.queryTime) ? "slow_query" : "query";
            }
        } catch (Exception e) {
            return isSlowQuery(event.queryTime) ? "slow_query" : "query";
        }
    }

    /**
     * Determines if a query is considered "slow" based on configuration
     */
    private boolean isSlowQuery(long queryTime) {
        return Config.enable_qe_slow_log && queryTime > Config.qe_slow_log_ms;
    }

    /**
     * Computes a digest (fingerprint) for a SQL statement
     */
    private String computeStatementDigest(String stmt) {
        SessionVariable sessionVariable = new SessionVariable();
        sessionVariable.setSqlMode(32);
        List<StatementBase> stmts = SqlParser.parse(stmt, sessionVariable);
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

    /**
     * Truncates a string to a maximum byte length while preserving UTF-8 character integrity.
     * This prevents invalid UTF-8 sequences when truncating strings.
     * 
     * @param str The string to truncate
     * @return The truncated string with valid UTF-8 characters
     */
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

