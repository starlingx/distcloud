#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Boolean, Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subclouds = Table("subclouds", meta, autoload=True)

    # Add the 'rehomed' column to the subclouds table.
    subclouds.create_column(Column("rehomed", Boolean, default=False))

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
