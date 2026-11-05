"""S3 or any S3-compatible store. Files never pass through the API: clients use presigned URLs."""

import aioboto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.configs.settings import get_settings

_session = aioboto3.Session()


def _client():
    s = get_settings()
    return _session.client(
        "s3",
        region_name=s.s3_region,
        endpoint_url=s.s3_endpoint,
        aws_access_key_id=s.s3_access_key_id,
        aws_secret_access_key=s.s3_secret_access_key,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path" if s.s3_force_path_style else "auto"}),
    )  # fmt: skip


async def create_upload_url(key: str, content_type: str, content_length: int) -> str:
    s = get_settings()
    params = {"Bucket": s.s3_bucket, "Key": key, "ContentType": content_type, "ContentLength": content_length}
    async with _client() as client:
        return await client.generate_presigned_url("put_object", Params=params, ExpiresIn=s.s3_upload_url_ttl_seconds)


async def create_download_url(key: str) -> str:
    s = get_settings()
    async with _client() as client:
        return await client.generate_presigned_url(
            "get_object", Params={"Bucket": s.s3_bucket, "Key": key}, ExpiresIn=s.s3_download_url_ttl_seconds
        )


async def get_object_size(key: str) -> int | None:
    async with _client() as client:
        try:
            head = await client.head_object(Bucket=get_settings().s3_bucket, Key=key)
        except ClientError as exc:
            if exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
                return None
            raise
        return head["ContentLength"]


async def delete_object(key: str) -> None:
    async with _client() as client:
        await client.delete_object(Bucket=get_settings().s3_bucket, Key=key)


def public_url(key: str) -> str | None:
    base = get_settings().s3_public_base_url
    return f"{base.rstrip('/')}/{key}" if base else None
