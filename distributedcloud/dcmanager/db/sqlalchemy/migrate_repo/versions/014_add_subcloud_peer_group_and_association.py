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

    # Declare the new system_peer table
    system_peer = sqlalchemy.Table(
        'system_peer', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True,
                          autoincrement=True,
                          nullable=False),
        sqlalchemy.Column('peer_uuid', sqlalchemy.String(36), unique=True),
        sqlalchemy.Column('peer_name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('manager_endpoint', sqlalchemy.String(255)),
        sqlalchemy.Column('manager_username', sqlalchemy.String(255)),
        sqlalchemy.Column('manager_password', sqlalchemy.String(255)),
        sqlalchemy.Column('peer_controller_gateway_ip', sqlalchemy.String(255)),
        sqlalchemy.Column('administrative_state', sqlalchemy.String(255)),
        sqlalchemy.Column('heartbeat_interval', sqlalchemy.Integer),
        sqlalchemy.Column('heartbeat_failure_threshold', sqlalchemy.Integer),
        sqlalchemy.Column('heartbeat_failure_policy', sqlalchemy.String(255)),
        sqlalchemy.Column('heartbeat_maintenance_timeout', sqlalchemy.Integer),
        sqlalchemy.Column('heartbeat_status', sqlalchemy.String(255)),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET
    )
    system_peer.create()


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
