#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    sync_lock = sqlalchemy.Table('sync_lock', meta, autoload=True)
    sync_lock.drop()


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade not supported.')
