#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    strategy_steps = sqlalchemy.Table("strategy_steps", meta, autoload=True)
    # Alter column length
    strategy_steps.c.details.alter(type=sqlalchemy.String(1000))


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
