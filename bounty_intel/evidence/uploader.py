"""Upload evidence files to Google Cloud Storage and generate signed URLs."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from bounty_intel.config import settings


def upload_to_gcs(local_path: Path, destination_prefix: str = "") -> str:
    """Upload a file to GCS and return the gs:// path."""
    from google.cloud import storage

    client = storage.Client()
    bucket = client.bucket(settings.gcs_bucket)

    if destination_prefix:
        blob_name = f"{destination_prefix}/{local_path.name}"
    else:
        blob_name = f"evidence/{local_path.name}"

    blob = bucket.blob(blob_name)
    blob.upload_from_filename(str(local_path))

    return f"gs://{settings.gcs_bucket}/{blob_name}"


def _get_service_account_email() -> str:
    """Get the service account email for IAM-based signing on Cloud Run."""
    import google.auth
    credentials, _ = google.auth.default()
    sa_email = getattr(credentials, "service_account_email", None)
    if sa_email and sa_email != "default" and "@" in sa_email:
        return sa_email
    # On Cloud Run, compute credentials return "default" — resolve via metadata
    import urllib.request
    req = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        headers={"Metadata-Flavor": "Google"},
    )
    with urllib.request.urlopen(req, timeout=2) as resp:
        return resp.read().decode()


def generate_signed_url(gcs_path: str, expiration_seconds: int | None = None) -> str:
    """Generate a signed URL for a GCS object.

    On Cloud Run (no local key file), uses the IAM signBlob API via the
    default service account. Locally, uses standard V4 signing with key file.
    """
    from google.cloud import storage

    if expiration_seconds is None:
        expiration_seconds = settings.gcs_signed_url_ttl

    bucket_name = gcs_path.split("/")[2]
    blob_name = "/".join(gcs_path.split("/")[3:])

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    # Try standard V4 signing first (works with local key files)
    try:
        return blob.generate_signed_url(
            version="v4",
            expiration=timedelta(seconds=expiration_seconds),
            method="GET",
        )
    except Exception:
        pass

    # On Cloud Run: use IAM signBlob API with the default service account
    sa_email = _get_service_account_email()

    import google.auth
    import google.auth.transport.requests

    credentials, _ = google.auth.default()
    credentials.refresh(google.auth.transport.requests.Request())

    return blob.generate_signed_url(
        version="v4",
        expiration=timedelta(seconds=expiration_seconds),
        method="GET",
        service_account_email=sa_email,
        access_token=credentials.token,
    )


def delete_from_gcs(gcs_path: str) -> bool:
    """Delete a file from Google Cloud Storage."""
    from google.cloud import storage

    try:
        bucket_name = gcs_path.split("/")[2]
        blob_name = "/".join(gcs_path.split("/")[3:])

        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)

        # Delete the blob
        blob.delete()
        return True

    except Exception as e:
        print(f"Failed to delete {gcs_path} from GCS: {e}")
        return False
