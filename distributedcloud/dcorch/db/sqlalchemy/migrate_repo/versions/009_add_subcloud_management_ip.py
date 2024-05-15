#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    subcloud = sqlalchemy.Table("subcloud", meta, autoload=True)

    # Add the management_ip attribute
    subcloud.create_column(sqlalchemy.Column("management_ip", sqlalchemy.String(64)))

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
