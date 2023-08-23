# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sqlalchemy

ENGINE = 'InnoDB',
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData(bind=migrate_engine)

    subclouds = sqlalchemy.Table('subclouds', meta, autoload=True)
    # Add the 'rehome_data' column to the subclouds table.
    subclouds.create_column(sqlalchemy.Column('rehome_data', sqlalchemy.Text))


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
