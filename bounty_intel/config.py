"""Configuration via environment variables with .env fallback."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database — set DATABASE_URL for local, or DB_USER/DB_PASSWORD/CLOUD_SQL_CONNECTION_NAME for Cloud Run
    database_url: str = ""
    db_user: str = "bounty_user"
    db_password: str = ""
    db_name: str = "bounty_intel"
    cloud_sql_connection_name: str = ""  # e.g. "project:region:instance"

    # GCP
    gcs_bucket: str = "julius-bounty-evidence"
    gcs_signed_url_ttl: int = 3600  # 1 hour

    # Security
    dev_mode: bool = False  # bypasses IAP check for local dev
    allowed_email: str = "julioxus@gmail.com"

    # Auth
    session_secret: str = ""  # for signing cookies
    google_client_id: str = ""
    google_client_secret: str = ""
    api_key: str = ""  # for programmatic /api/ access from skills

    # API mode (for skills running locally — set this to use HTTP instead of direct DB)
    bounty_intel_api_url: str = ""  # e.g. "https://bounty-dashboard-887002731862.europe-west1.run.app"
    bounty_intel_api_key: str = ""  # API key for auth

    # Platform API credentials
    hackerone_username: str = ""
    hackerone_api_token: str = ""
    intigriti_cookie: str = ""
    intigriti_pat: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    def get_database_url(self) -> str:
        """Build database URL, supporting Cloud Run Unix socket."""
        if self.database_url:
            return self.database_url
        if self.cloud_sql_connection_name and self.db_password:
            # Cloud Run: Cloud SQL Auth Proxy exposes Unix socket
            socket_path = f"/cloudsql/{self.cloud_sql_connection_name}"
            return f"postgresql+psycopg2://{self.db_user}:{self.db_password}@/{self.db_name}?host={socket_path}"
        return "postgresql://postgres:dev@localhost:5432/bounty_intel"


settings = Settings()
