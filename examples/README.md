
## Build
```shell

# flash-fe
docker run -it -v ~/.m2:/root/.m2 -v ./:/root/starrocks starrocks/dev-env-ubuntu:latest
cd /root/starrocks/
./build.sh --fe

DOCKER_BUILDKIT=1 docker build \
    --build-arg ARTIFACT_SOURCE=local \
    --build-arg LOCAL_REPO_PATH=. \
    -f docker/dockerfiles/fe/fe-ubuntu.Dockerfile \
    -t flash-fe:0.0.1 .
```


## Archives

```shell

## CN Config
      echo enable_load_volume_from_conf = true /opt/starrocks/fe/conf/fe.conf &&      
      echo aws_s3_path = starrocks >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_endpoint = minio:9000 >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_access_key = minioadmin >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_secret_key = minioadmin >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_enable_partitioned_prefix = false >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_region = us-east-1 >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_use_instance_profile = false >> /opt/starrocks/fe/conf/fe.conf &&
      
      echo cloud_native_storage_type = S3 >> /opt/starrocks/fe/conf/fe.conf &&
      echo aws_s3_use_aws_sdk_default_behavior = true >> /opt/starrocks/fe/conf/fe.conf &&
```

## Query Commands
```yaml
grant USAGE on catalog iceberg02 to role reader;
grant select on *.* to role reader;
```
