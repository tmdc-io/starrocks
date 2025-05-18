## Stand Up
```shell

# MinIO / Rest
docker-compose -f examples/docker-compose.setup.yml up -d
# Flash
docker-compose -f examples/docker-compose.flash.yml up        
```

## Queries

```shell

mysql -P9030 -h127.0.0.1 -uroot \
    --default-auth mysql_clear_password \
    --enable-cleartext-plugin         
```


```shell

# set-up default storage volume for `shared` catalog
CREATE STORAGE VOLUME vol_01
TYPE = S3
LOCATIONS = ("s3://flash")
PROPERTIES (
    "enabled" = "true",
    "aws.s3.region" = "us-east-1",
    "aws.s3.endpoint" = "http://minio:9000",
    "aws.s3.access_key" = "admin",
    "aws.s3.secret_key" = "password",
    "aws.s3.enable_partitioned_prefix" = "false"
);
SET vol_01 AS DEFAULT STORAGE VOLUME;
```

```shell

# set-up iceberg catalog
DROP CATALOG iceberg;
CREATE EXTERNAL CATALOG 'iceberg'
COMMENT 'MinIO backed Iceberg catalog'
PROPERTIES (
  "type" = "iceberg",
  "iceberg.catalog.type" = "rest",
  "iceberg.catalog.uri" = "http://iceberg-rest:8181/",
  "iceberg.catalog.warehouse" = "warehouse",
  "aws.s3.access_key" = "admin",
  "aws.s3.secret_key" = "password",
  "aws.s3.endpoint" = "http://minio:9000",
  "aws.s3.region" = "us-east-1",
  "aws.s3.enable_path_style_access" = "false",
  "client.factory" = "com.starrocks.connector.share.iceberg.IcebergAwsClientFactory",
  "dataos.depot.address" = "dataos://depot?purpose=read",
  "dataos.disable_heimdall" = "false"
);
SHOW CATALOGS;    
```

````shell

# test iceberg
SET CATALOG iceberg;
CREATE DATABASE test;
USE test;
CREATE TABLE dummy(id int, name string);
INSERT INTO dummy VALUES (2, 'dummy-value');
SELECT * FROM dummy;
````
