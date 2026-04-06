"""Database schema creation and migration utilities."""

from bounty_intel.db import Base, create_all_tables, get_engine


def create_schema():
    """Create all tables. Safe to call multiple times (uses IF NOT EXISTS)."""
    create_all_tables()
    print("Schema created successfully.")


def drop_schema():
    """Drop all tables. USE WITH CAUTION."""
    Base.metadata.drop_all(get_engine())
    print("All tables dropped.")


if __name__ == "__main__":
    create_schema()
