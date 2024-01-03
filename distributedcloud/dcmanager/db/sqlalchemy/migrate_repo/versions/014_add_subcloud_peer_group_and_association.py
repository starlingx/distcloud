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

    # Declare the new subcloud_peer_group table
    subcloud_peer_group = sqlalchemy.Table(
        'subcloud_peer_group', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True,
                          autoincrement=True,
                          nullable=False),
        sqlalchemy.Column('peer_group_name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('group_priority', sqlalchemy.Integer),
        sqlalchemy.Column('group_state', sqlalchemy.String(255)),
        sqlalchemy.Column('system_leader_id', sqlalchemy.String(255)),
        sqlalchemy.Column('system_leader_name', sqlalchemy.String(255)),
        sqlalchemy.Column('max_subcloud_rehoming', sqlalchemy.Integer),
        sqlalchemy.Column('migration_status', sqlalchemy.String(255)),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET
    )
    subcloud_peer_group.create()
    # Add the 'peer_greoup_id' column to the subclouds table.
    subclouds.create_column(sqlalchemy.Column('peer_group_id', sqlalchemy.Integer))

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
        sqlalchemy.Column('availability_state', sqlalchemy.String(255)),
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

    # Declare the new peer_group_association table
    peer_group_association = sqlalchemy.Table(
        'peer_group_association', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True,
                          autoincrement=True,
                          nullable=False),
        sqlalchemy.Column('peer_group_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('subcloud_peer_group.id',
                                                ondelete='CASCADE')),
        sqlalchemy.Column('system_peer_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('system_peer.id',
                                                ondelete='CASCADE')),
        sqlalchemy.Column('peer_group_priority', sqlalchemy.Integer),
        sqlalchemy.Column('association_type', sqlalchemy.String(255)),
        sqlalchemy.Column('sync_status', sqlalchemy.String(255)),
        sqlalchemy.Column('sync_message', sqlalchemy.Text),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET
    )
    peer_group_association.create()


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
