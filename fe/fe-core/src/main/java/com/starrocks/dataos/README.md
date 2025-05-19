# StarRocks DataOS Integration

This package provides integration between StarRocks and the DataOS platform, enabling seamless security, data access, and monitoring capabilities.

## Overview

The `com.starrocks.dataos` package serves as a bridge between StarRocks and DataOS services, allowing StarRocks to leverage DataOS platform capabilities for enhanced security, data access, and operational observability. This integration enables centralized identity management, policy enforcement, secure access to external data sources, and comprehensive query auditing.

## Key Components

### Security Components

* **HeimdallAuthenticationProvider**: Implements authentication using DataOS Heimdall service
  * Validates user credentials against the Heimdall authentication service
  * Supports API key-based authentication
  * Integrates with StarRocks' authentication system

* **HeimdallAccessController**: Extends StarRocks' native authorization system with DataOS Heimdall integration
  * Implements fine-grained access control at catalog, database, and table levels
  * Provides column masking for data redaction
  * Enables row-level security for filtering data based on user context
  * Uses a hybrid approach with native permissions for internal catalogs and Heimdall for external resources

### Data Integration Components

* **DataOSClient**: Central integration point for all DataOS platform services
  * Handles authentication and authorization with Heimdall
  * Resolves data source locations and credentials via Depot Resolver
  * Manages secure access to cloud storage credentials via Secret Manager
  * Enforces data access policies at various levels

* **Constants**: Defines constant values used throughout the DataOS integration

### Audit Components

* **AuditTableLoaderPlugin**: Captures and persists query audit events
  * Extends StarRocks' audit system to store detailed query information
  * Processes various event types (queries, connections, etc.)
  * Computes query fingerprints for pattern analysis
  * Integrates with the audit table infrastructure

* **AuditTableManager**: Sets up and maintains the audit database infrastructure
  * Creates and manages the `_audit_` database and `query_log` table
  * Defines the schema for audit events
  * Configures dynamic partitioning for efficient storage

* **AuditStreamLoader**: Handles loading audit data into StarRocks using Stream Load
  * Manages HTTP communication with StarRocks nodes
  * Handles redirection between frontend and backend nodes
  * Ensures reliable persistence of audit data

## Architecture

The DataOS integration follows a layered architecture:

1. **Authentication Layer**: Validates user identity via HeimdallAuthenticationProvider
2. **Authorization Layer**: Enforces access policies via HeimdallAccessController
3. **Integration Layer**: Provides access to DataOS services via DataOSClient
4. **Audit Layer**: Captures and stores detailed query information

Each layer integrates with StarRocks' existing systems through well-defined extension points, ensuring clean separation of concerns while adding DataOS platform capabilities.

## Security Features

The DataOS integration enhances StarRocks security with:

* **Centralized Identity Management**: User authentication delegated to Heimdall service
* **Fine-Grained Access Control**: Permissions at catalog, database, table, column, and row levels
* **Data Redaction**: Dynamic transformation of sensitive data based on user permissions
* **Row-Level Security**: Filtering of data rows based on user context and policy rules
* **Secure Credential Management**: Access to external systems without exposing credentials

## Audit Capabilities

The audit components provide:

* **Comprehensive Query Logging**: Detailed tracking of all query activity
* **Categorized Events**: Classification of events as regular queries, slow queries, or connections
* **Resource Metrics**: Capture of CPU, memory, scan volumes, and other performance metrics
* **Query Fingerprinting**: Normalization of SQL patterns for identifying similar queries
* **Materialized View Usage Tracking**: Visibility into MV candidate evaluation and hits
* **Big Query Detection**: Identification of resource-intensive queries
* **Efficient Storage**: Dynamic partitioning and optimized schemas for audit data

## Usage

The DataOS integration activates automatically when StarRocks is deployed within a DataOS environment, with configuration determined by environment variables and settings in the DataOS platform.

### Security Configuration

Security features are enabled when the Heimdall authentication plugin is configured:

```sql
CREATE USER 'user'@'%' IDENTIFIED BY AUTH_PLUGIN 'HEIMDALL' AS 'heimdall_user';
```

### Audit Configuration

Audit settings can be customized via session or global variables:

```sql
-- Enable big query logging
SET GLOBAL enable_big_query_log = true;

-- Set threshold for CPU time (in seconds)
SET GLOBAL big_query_log_cpu_second_threshold = 600;

-- Set threshold for scanned bytes
SET GLOBAL big_query_log_scan_bytes_threshold = 10737418240;
```

## Integration Points

The DataOS package integrates with StarRocks at these key points:

1. **Authentication System**: Via AuthenticationProvider interface
2. **Authorization System**: Via AccessController interface
3. **Catalog System**: For resolving external data sources
4. **Query Execution**: For audit event capture and policy enforcement
5. **Stream Load**: For persisting audit data

These integration points allow DataOS capabilities to be added to StarRocks without modifying core components. 