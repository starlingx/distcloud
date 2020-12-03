# Copyright (c) 2015 Ericsson AB.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from dccommon.drivers.openstack import vim
import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    subclouds = sqlalchemy.Table(
        'subclouds', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('description', sqlalchemy.String(255)),
        sqlalchemy.Column('location', sqlalchemy.String(255)),
        sqlalchemy.Column('software_version', sqlalchemy.String(255)),
        sqlalchemy.Column('management_state', sqlalchemy.String(255)),
        sqlalchemy.Column('availability_status', sqlalchemy.String(255)),
        sqlalchemy.Column('management_subnet', sqlalchemy.String(255)),
        sqlalchemy.Column('management_gateway_ip', sqlalchemy.String(255)),
        sqlalchemy.Column('management_start_ip', sqlalchemy.String(255)),
        sqlalchemy.Column('management_end_ip', sqlalchemy.String(255)),
        sqlalchemy.Column('systemcontroller_gateway_ip',
                          sqlalchemy.String(255)),
        sqlalchemy.Column('audit_fail_count', sqlalchemy.Integer, default=0),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    subcloud_status = sqlalchemy.Table(
        'subcloud_status', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('subcloud_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('subclouds.id',
                                                ondelete='CASCADE')),
        sqlalchemy.Column('endpoint_type', sqlalchemy.String(255)),
        sqlalchemy.Column('sync_status', sqlalchemy.String(255)),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    sw_update_strategy = sqlalchemy.Table(
        'sw_update_strategy', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('type', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('subcloud_apply_type', sqlalchemy.String(255)),
        sqlalchemy.Column('max_parallel_subclouds', sqlalchemy.Integer),
        sqlalchemy.Column('stop_on_failure', sqlalchemy.Boolean),
        sqlalchemy.Column('state', sqlalchemy.String(255)),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    sw_update_opts_default = sqlalchemy.Table(
        'sw_update_opts_default', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('subcloud_id', sqlalchemy.Integer),
        sqlalchemy.Column('storage_apply_type', sqlalchemy.String(255)),
        sqlalchemy.Column('compute_apply_type', sqlalchemy.String(255)),
        sqlalchemy.Column('max_parallel_computes', sqlalchemy.Integer),
        sqlalchemy.Column('default_instance_action', sqlalchemy.String(255)),
        sqlalchemy.Column('alarm_restriction_type', sqlalchemy.String(255)),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    sw_update_opts = sqlalchemy.Table(
        'sw_update_opts', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('subcloud_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('subclouds.id',
                                                ondelete='CASCADE')),
        sqlalchemy.Column('storage_apply_type', sqlalchemy.String(255)),
        sqlalchemy.Column('compute_apply_type', sqlalchemy.String(255)),
        sqlalchemy.Column('max_parallel_computes', sqlalchemy.Integer),
        sqlalchemy.Column('default_instance_action', sqlalchemy.String(255)),
        sqlalchemy.Column('alarm_restriction_type', sqlalchemy.String(255)),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    strategy_steps = sqlalchemy.Table(
        'strategy_steps', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('subcloud_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('subclouds.id',
                                                ondelete='CASCADE'),
                          unique=True),
        sqlalchemy.Column('stage', sqlalchemy.Integer),
        sqlalchemy.Column('state', sqlalchemy.String(255)),
        sqlalchemy.Column('details', sqlalchemy.String(255)),
        sqlalchemy.Column('started_at', sqlalchemy.DateTime),
        sqlalchemy.Column('finished_at', sqlalchemy.DateTime),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    tables = (
        subclouds,
        subcloud_status,
        sw_update_strategy,
        strategy_steps,
        sw_update_opts,
        sw_update_opts_default
    )

    for index, table in enumerate(tables):
        try:
            table.create()
        except Exception:
            # If an error occurs, drop all tables created so far to return
            # to the previously existing state.
            meta.drop_all(tables=tables[:index])
            raise

    try:
        # populate the sw_update_opts_default with the default values.
        con = migrate_engine.connect()

        con.execute(sw_update_opts_default.insert(),  # pylint: disable=E1120
                    storage_apply_type=vim.APPLY_TYPE_PARALLEL,
                    compute_apply_type=vim.APPLY_TYPE_PARALLEL,
                    max_parallel_computes=10,
                    default_instance_action=vim.INSTANCE_ACTION_MIGRATE,
                    alarm_restriction_type=vim.ALARM_RESTRICTIONS_RELAXED,
                    deleted=0)
    except Exception:
        # We can survive if this fails.
        pass


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade not supported - '
                              'would drop all tables')
