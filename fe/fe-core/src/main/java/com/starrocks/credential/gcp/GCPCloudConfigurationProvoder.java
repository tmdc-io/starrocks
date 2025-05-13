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

package com.starrocks.credential.gcp;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.starrocks.common.DdlException;
import com.starrocks.credential.CloudConfiguration;
import com.starrocks.credential.CloudConfigurationProvider;
import com.starrocks.dataos.Constants;
import com.starrocks.server.GlobalStateMgr;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

import static com.starrocks.connector.share.credential.CloudConfigurationConstants.GCP_GCS_SERVICE_ACCOUNT_EMAIL;
import static com.starrocks.connector.share.credential.CloudConfigurationConstants.GCP_GCS_SERVICE_ACCOUNT_IMPERSONATION_SERVICE_ACCOUNT;
import static com.starrocks.connector.share.credential.CloudConfigurationConstants.GCP_GCS_SERVICE_ACCOUNT_PRIVATE_KEY;
import static com.starrocks.connector.share.credential.CloudConfigurationConstants.GCP_GCS_SERVICE_ACCOUNT_PRIVATE_KEY_ID;
import static com.starrocks.connector.share.credential.CloudConfigurationConstants.GCP_GCS_USE_COMPUTE_ENGINE_SERVICE_ACCOUNT;

public class GCPCloudConfigurationProvoder implements CloudConfigurationProvider {
    private static final Logger LOG = LogManager.getLogger(GCPCloudConfigurationProvoder.class);

    @Override
    public CloudConfiguration build(Map<String, String> properties) {
        Preconditions.checkNotNull(properties);

        // DataOS Heimdall
        // resolve dataos.secret, if supplied
        String secret = properties.get(Constants.DATAOS_SECRET);
        if (!Strings.isNullOrEmpty(secret)) {
            try {
                Map<String, String> m = GlobalStateMgr.getCurrentState().getDataOSClient()
                        .resolveSecretForGcp(secret);
                if (m != null && !m.isEmpty()) {
                    properties.putAll(m); // Copy all the keys
                }
            } catch (DdlException de) {
                LOG.error("Error in resolving DataOS secret: " + secret, de);
            }
        }

        GCPCloudCredential gcpCloudCredential = new GCPCloudCredential(
                Boolean.parseBoolean(properties.getOrDefault(GCP_GCS_USE_COMPUTE_ENGINE_SERVICE_ACCOUNT, "false")),
                properties.getOrDefault(GCP_GCS_SERVICE_ACCOUNT_EMAIL, ""),
                properties.getOrDefault(GCP_GCS_SERVICE_ACCOUNT_PRIVATE_KEY_ID, ""),
                properties.getOrDefault(GCP_GCS_SERVICE_ACCOUNT_PRIVATE_KEY, ""),
                properties.getOrDefault(GCP_GCS_SERVICE_ACCOUNT_IMPERSONATION_SERVICE_ACCOUNT, "")
        );
        if (!gcpCloudCredential.validate()) {
            return null;
        }
        return new GCPCloudConfiguration(gcpCloudCredential);
    }
}
