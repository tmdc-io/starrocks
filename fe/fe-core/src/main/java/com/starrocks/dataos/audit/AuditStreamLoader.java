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

import com.google.common.base.Joiner;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;

/**
 * AuditStreamLoader is responsible for loading audit data into StarRocks using the Stream Load API.
 * <p>
 * It handles the HTTP communication with StarRocks FE (Frontend) nodes, which may redirect
 * to BE (Backend) nodes to complete the loading process. The loader supports:
 * <p>
 * 1. Creating proper HTTP connections with appropriate headers
 * 2. Following redirects from FE to BE nodes
 * 3. Streaming data in JSON format
 * 4. Processing response messages
 * <p>
 * This class is used by AuditTableLoaderPlugin to persist batches of audit events.
 */
public class AuditStreamLoader {
    private static final Logger LOG = LogManager.getLogger(AuditStreamLoader.class);

    private final List<String> columns;
    private final String loadUrlStr;
    private final String authEncoding;
    private final String feIdentity;

    // Connection timeouts
    public int connectTimeout = 1000;  // Connection timeout in milliseconds
    public int readTimeout = 1000;     // Read timeout in milliseconds
    public String streamLoadFilter = ""; // Optional filter for stream load

    /**
     * Constructor for AuditStreamLoader
     * 
     * @param hostPort Host and port of the StarRocks FE node
     * @param user Username for authentication
     * @param passwd Password for authentication
     * @param columns List of column names in the audit table
     */
    public AuditStreamLoader(String hostPort, String user, String passwd, List<String> columns) {
        this.columns = columns;

        String loadUrlPattern = "http://%s/api/%s/%s/_stream_load?";
        this.loadUrlStr = String.format(loadUrlPattern, hostPort,
                AuditTableManager.AUDIT_DB_NAME,
                AuditTableManager.AUDIT_TBL_NAME);

        this.authEncoding = Base64.getEncoder().encodeToString(String.format("%s:%s", user, passwd)
                .getBytes(StandardCharsets.UTF_8));

        this.feIdentity = "__builtin__";
    }

    /**
     * Creates an HTTP connection with appropriate headers for stream loading
     * 
     * @param urlStr URL for the connection
     * @param label Label to identify this load job
     * @return Configured HttpURLConnection
     * @throws IOException If connection setup fails
     */
    private HttpURLConnection getConnection(String urlStr, String label) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("Authorization", "Basic " + authEncoding);
        conn.addRequestProperty("Expect", "100-continue");
        conn.addRequestProperty("Content-Type", "text/plain; charset=UTF-8");
        conn.addRequestProperty("format", "json");
        conn.addRequestProperty("strip_outer_array", "true");

        conn.addRequestProperty("label", label);
        conn.addRequestProperty("max_filter_ratio", "1.0");
        conn.addRequestProperty("columns", Joiner.on(",").join(this.columns));
        if (!StringUtils.isBlank(this.streamLoadFilter)) {
            conn.addRequestProperty("where", streamLoadFilter);
        }

        conn.setDoOutput(true);
        conn.setDoInput(true);

        conn.setConnectTimeout(connectTimeout);
        conn.setReadTimeout(readTimeout);

        return conn;
    }

    /**
     * Reads the response content from an HTTP connection
     * 
     * @param conn The HTTP connection
     * @return Response content as string
     */
    private String getContent(HttpURLConnection conn) {
        BufferedReader br = null;
        StringBuilder response = new StringBuilder();
        String line;
        try {
            if (100 <= conn.getResponseCode() && conn.getResponseCode() <= 399) {
                br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            } else {
                br = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            }
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        } catch (IOException e) {
            LOG.warn("get content error,", e);
        }

        return response.toString();
    }

    /**
     * Loads a batch of audit events into StarRocks
     * <p>
     * This method:
     * 1. Creates a unique label for the load job
     * 2. Connects to the FE node
     * 3. Follows a redirect to a BE node if needed
     * 4. Sends the JSON data
     * 5. Processes the response
     *
     * @param sb StringBuilder containing the JSON data to load
     * @return LoadResponse object containing the result status and message
     */
    public LoadResponse loadBatch(StringBuilder sb) {
        Calendar calendar = Calendar.getInstance();

        // label length limit is less than 128 , audit_%s%02d%02d_%02d%02d%02d_ length is 22
        String labelId = this.feIdentity.length() > 106
                ? UUID.randomUUID().toString().replaceAll("-", "")
                : this.feIdentity;

        String label = String.format("audit_%s%02d%02d_%02d%02d%02d_%s",
                calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH) + 1, calendar.get(Calendar.DAY_OF_MONTH),
                calendar.get(Calendar.HOUR_OF_DAY), calendar.get(Calendar.MINUTE), calendar.get(Calendar.SECOND),
                labelId);

        HttpURLConnection feConn = null;
        HttpURLConnection beConn = null;
        try {
            LOG.info("Loading {} audit events...", sb.length());
            // build request and send to fe
            feConn = getConnection(loadUrlStr, label);
            // print curl load command in fe.log
            // LOG.info(toCurl(feConn));
            int status = feConn.getResponseCode();
            // fe send back http response code TEMPORARY_REDIRECT 307 and new be location, or response code HTTP_OK 200 from nginx
            if (status != 307 && status != HttpURLConnection.HTTP_OK) {
                throw new Exception("status is not TEMPORARY_REDIRECT 307 or HTTP_OK 200, status: " + status
                        + ", response: " + getContent(feConn));
            }
            String location = feConn.getHeaderField("Location");
            if (status == 307 && location == null) {
                throw new Exception("redirect location is null");
            }
            // build request and send to new be location, or use old conn if status is 200
            beConn = status == 307 ? getConnection(location, label) : getConnection(loadUrlStr, label);
            // send data to be
            BufferedOutputStream bos = new BufferedOutputStream(beConn.getOutputStream());
            String content = "[" + sb.toString() + "]";
            bos.write(content.getBytes());
            bos.close();

            // get respond
            status = beConn.getResponseCode();
            String respMsg = beConn.getResponseMessage();
            String response = getContent(beConn);

            return new LoadResponse(status, respMsg, response);

        } catch (Exception e) {
            // TODO: Better error logging
            e.printStackTrace();
            String err = "failed to load audit events via AuditTableLoaderPlugin plugin with label: " + label;
            LOG.warn(err, e);
            return new LoadResponse(-1, e.getMessage(), err);
        } finally {
            if (feConn != null) {
                feConn.disconnect();
            }
            if (beConn != null) {
                beConn.disconnect();
            }
        }
    }

    /**
     * Response object for stream load operations
     */
    public static class LoadResponse {
        public int status;         // HTTP status code
        public String respMsg;     // Response message
        public String respContent; // Response content

        public LoadResponse(int status, String respMsg, String respContent) {
            this.status = status;
            this.respMsg = respMsg;
            this.respContent = respContent;
        }

        @Override
        public String toString() {
            return "status: " + status +
                    ", resp msg: " + respMsg +
                    ", resp content: " + respContent;
        }
    }
}
