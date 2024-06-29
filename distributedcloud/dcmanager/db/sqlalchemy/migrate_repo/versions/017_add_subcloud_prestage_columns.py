#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table, String


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subclouds = Table("subclouds", meta, autoload=True)

    # Add the 'prestage_status' and 'prestage_versions' columns to
    # the subclouds table.
    subclouds.create_column(Column("prestage_status", String(255)))
    subclouds.create_column(Column("prestage_versions", String(255)))

    # Update existing subclouds that have the old prestaging deploy status
    subclouds.update().where(  # pylint: disable=E1120
        subclouds.c.deploy_status.like("prestage%")
    ).values({"deploy_status": "complete"}).execute()

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
