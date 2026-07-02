import io

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from config import settings


def _client():
    return boto3.client(
        "s3",
        endpoint_url=f"http://{settings.minio_endpoint}",
        aws_access_key_id=settings.minio_access_key,
        aws_secret_access_key=settings.minio_secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def ensure_bucket():
    client = _client()
    try:
        client.head_bucket(Bucket=settings.minio_bucket)
    except ClientError:
        client.create_bucket(Bucket=settings.minio_bucket)


def upload_apk(file_bytes: bytes, object_name: str) -> str:
    ensure_bucket()
    _client().put_object(
        Bucket=settings.minio_bucket,
        Key=object_name,
        Body=io.BytesIO(file_bytes),
        ContentLength=len(file_bytes),
        ContentType="application/vnd.android.package-archive",
    )
    return f"{settings.minio_bucket}/{object_name}"


def download_apk(object_name: str) -> bytes:
    resp = _client().get_object(Bucket=settings.minio_bucket, Key=object_name)
    return resp["Body"].read()


def delete_apk(object_name: str):
    _client().delete_object(Bucket=settings.minio_bucket, Key=object_name)
