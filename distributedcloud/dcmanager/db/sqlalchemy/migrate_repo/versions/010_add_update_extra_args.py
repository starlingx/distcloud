#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    # Add the 'extra_args' column to the sw_update_strategy table.
    sw_update_strategy = sqlalchemy.Table('sw_update_strategy',
                                          meta,
                                          autoload=True)
    # JSONEncodedDict is stored in the database as Text
    sw_update_strategy.create_column(sqlalchemy.Column('extra_args',
                                                       sqlalchemy.Text))
    return True


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
