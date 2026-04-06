"""Database schema creation and migration utilities."""

from bounty_intel.db import Base, create_all_tables, get_engine


def create_schema():
    """Create all tables. Safe to call multiple times (uses IF NOT EXISTS)."""
    create_all_tables()
    _add_missing_columns()
    print("Schema created successfully.")


def _add_missing_columns():
    """Add columns introduced after initial schema. Safe to re-run."""
    from sqlalchemy import text
    with get_engine().connect() as conn:
        # logo_url on programs (added 2026-04-06)
        conn.execute(text(
            "ALTER TABLE programs ADD COLUMN IF NOT EXISTS logo_url TEXT DEFAULT ''"
        ))
        # local_path on evidence_files + relax gcs_path (added 2026-04-06)
        conn.execute(text(
            "ALTER TABLE evidence_files ADD COLUMN IF NOT EXISTS local_path TEXT DEFAULT ''"
        ))
        conn.execute(text(
            "ALTER TABLE evidence_files ALTER COLUMN gcs_path DROP NOT NULL"
        ))
        conn.commit()


def drop_schema():
    """Drop all tables. USE WITH CAUTION."""
    Base.metadata.drop_all(get_engine())
    print("All tables dropped.")


if __name__ == "__main__":
    create_schema()
