#
# Copyright (c) 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table, String, DateTime


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subclouds = Table("subclouds", meta, autoload=True)

    # Add the backup-related columns to the subclouds table.
    subclouds.create_column(Column("backup_status", String(255)))
    subclouds.create_column(Column("backup_datetime", DateTime(timezone=False)))

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
