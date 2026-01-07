#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table

ENGINE = ("InnoDB",)
CHARSET = "utf8"


def upgrade(migrate_engine):
    """Create the subcloud_backup_config table with default values."""
    meta = MetaData()
    meta.bind = migrate_engine

    # Create the subcloud_backup_config table
    subcloud_backup_config = Table(
        "subcloud_backup_config",
        meta,
        Column("id", Integer, primary_key=True, autoincrement=True, nullable=False),
        Column("storage_location", String(64), nullable=False, default="local"),
        Column("retention_count", Integer, nullable=False, default=1),
        Column("created_at", DateTime),
        Column("updated_at", DateTime),
        Column("deleted_at", DateTime),
        Column("deleted", Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    subcloud_backup_config.create()

    # Insert the default configuration (single row with id=1)
    with migrate_engine.begin() as conn:
        conn.execute(
            subcloud_backup_config.insert().values(
                id=1, storage_location="dc-vault", retention_count=1, deleted=0
            )
        )

    # postgres does not increment the subcloud_backup_config id sequence
    # after the insert above as part of the migrate.
    # Note: use different SQL syntax if using mysql or sqlite
    if migrate_engine.name == "postgresql":
        with migrate_engine.begin() as conn:
            conn.execute("ALTER SEQUENCE subcloud_backup_config_id_seq RESTART WITH 2")

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
