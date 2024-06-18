#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    subcloud = sqlalchemy.Table("subclouds", meta, autoload=True)
    # Add the external_oam_subnet_ip_family column
    subcloud.create_column(
        sqlalchemy.Column("external_oam_subnet_ip_family", sqlalchemy.String(255))
    )


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
