#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)

ENGINE = ("InnoDB",)
CHARSET = "utf8"


def upgrade(migrate_engine):
    """Create the subcloud_backup_archive table with proper indexes."""
    meta = MetaData()
    meta.bind = migrate_engine

    _ = Table("subclouds", meta, autoload=True)

    # Create the subcloud_backup_archive table
    subcloud_backup_archive = Table(
        "subcloud_backup_archive",
        meta,
        Column("id", Integer, primary_key=True, autoincrement=True, nullable=False),
        Column("backup_id", String(255), nullable=False, unique=True),
        Column(
            "subcloud_id",
            Integer,
            ForeignKey("subclouds.id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("release_version", String(32), nullable=False),
        Column("created_at", DateTime(timezone=False), nullable=False),
        Column("size_bytes", BigInteger),
        Column("storage_location", String(64), nullable=False),
        Column("storage_path", Text, nullable=False),
        Column("updated_at", DateTime),
        Column("deleted_at", DateTime),
        Column("deleted", Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    subcloud_backup_archive.create()

    # Index on (subcloud_id, release_version) for filtering and grouping
    idx_subcloud_release = Index(
        "idx_backup_archive_subcloud_release",
        subcloud_backup_archive.c.subcloud_id,
        subcloud_backup_archive.c.release_version,
    )
    idx_subcloud_release.create(migrate_engine)

    # Index on created_at for sorting (most recent first)
    idx_created_at = Index(
        "idx_backup_archive_created_at",
        subcloud_backup_archive.c.created_at,
    )
    idx_created_at.create(migrate_engine)

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
