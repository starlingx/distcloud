# Copyright (c) 2017-2018 Wind River Inc.
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

import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    subcloud = sqlalchemy.Table(
        'subcloud', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('region_name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('software_version', sqlalchemy.String(255)),

        sqlalchemy.Column('management_state', sqlalchemy.String(64)),
        sqlalchemy.Column('availability_status', sqlalchemy.String(64),
                          default="offline"),
        sqlalchemy.Column('capabilities', sqlalchemy.Text),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),

        sqlalchemy.Index('subcloud_region_name_idx', 'region_name'),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    subcloud_alarms = sqlalchemy.Table(
        'subcloud_alarms', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('region_name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('critical_alarms', sqlalchemy.Integer),
        sqlalchemy.Column('major_alarms', sqlalchemy.Integer),
        sqlalchemy.Column('minor_alarms', sqlalchemy.Integer),
        sqlalchemy.Column('warnings', sqlalchemy.Integer),
        sqlalchemy.Column('cloud_status', sqlalchemy.String(64)),
        sqlalchemy.Column('capabilities', sqlalchemy.Text),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),

        sqlalchemy.Index('subcloud_alarm_region_name_idx', 'region_name'),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    resource = sqlalchemy.Table(
        'resource', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('resource_type', sqlalchemy.String(128)),
        sqlalchemy.Column('master_id', sqlalchemy.String(255)),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        sqlalchemy.Column('capabilities', sqlalchemy.Text),

        sqlalchemy.Index('resource_resource_type_idx', 'resource_type'),
        sqlalchemy.Index('resource_master_id_idx', 'master_id'),
        sqlalchemy.UniqueConstraint(
            'resource_type', 'master_id', 'deleted',
            name='uniq_resource0resource_type0master_id0deleted'),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    subcloud_resource = sqlalchemy.Table(
        'subcloud_resource', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('subcloud_resource_id', sqlalchemy.String(255)),

        # Could have also gotten this from subcloud.region_name
        sqlalchemy.Column('subcloud_name', sqlalchemy.String(255)),
        # Is this resource managed or unmanaged
        sqlalchemy.Column('shared_config_state', sqlalchemy.String(64),
                          default="managed"),
        sqlalchemy.Column('capabilities', sqlalchemy.Text),

        sqlalchemy.Column('resource_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('resource.id',
                                                ondelete='CASCADE')),
        # primary_key=True),
        sqlalchemy.Column('subcloud_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('subcloud.id',
                                                ondelete='CASCADE')),
        # primary_key=True),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),

        sqlalchemy.Index('subcloud_resource_resource_id_idx', 'resource_id'),
        sqlalchemy.UniqueConstraint(
            'resource_id', 'subcloud_id',
            name='uniq_subcloud_resource0resource_id0subcloud_id'),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    orch_job = sqlalchemy.Table(
        'orch_job', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('user_id', sqlalchemy.String(128)),
        sqlalchemy.Column('project_id', sqlalchemy.String(128)),

        # filledin by x_orch_api
        sqlalchemy.Column('endpoint_type', sqlalchemy.String(255),
                          nullable=False),
        # sqlalchemy.Column('resource_type', sqlalchemy.String(255),
        #                   nullable=False),

        sqlalchemy.Column('source_resource_id', sqlalchemy.String(255)),
        # http type: e.g. post/put/patch/delete
        sqlalchemy.Column('operation_type', sqlalchemy.String(255)),

        sqlalchemy.Column('resource_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('resource.id')),

        sqlalchemy.Column('resource_info', sqlalchemy.Text),
        sqlalchemy.Column('capabilities', sqlalchemy.Text),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),
        sqlalchemy.Index('orch_job_endpoint_type_idx', 'endpoint_type'),
        # sqlalchemy.Index('orch_job_resource_type_idx', 'resource_type'),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    orch_request = sqlalchemy.Table(
        'orch_request', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('state', sqlalchemy.String(128)),
        sqlalchemy.Column('try_count', sqlalchemy.Integer, default=0),
        sqlalchemy.Column('api_version', sqlalchemy.String(128)),
        sqlalchemy.Column('target_region_name', sqlalchemy.String(255)),
        sqlalchemy.Column('capabilities', sqlalchemy.Text),

        sqlalchemy.Column('orch_job_id', sqlalchemy.Integer,
                          sqlalchemy.ForeignKey('orch_job.id')),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),

        sqlalchemy.Index('orch_request_idx', 'state'),
        sqlalchemy.UniqueConstraint(
            'target_region_name', 'orch_job_id', 'deleted',
            name='uniq_orchreq0target_region_name0orch_job_id0deleted'),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    tables = (
        subcloud,
        subcloud_alarms,
        resource,
        subcloud_resource,
        orch_job,
        orch_request
    )

    for index, table in enumerate(tables):
        try:
            table.create()
        except Exception:
            # If an error occurs, drop all tables created so far to return
            # to the previously existing state.
            meta.drop_all(tables=tables[:index])
            raise


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade not supported - '
                              'would drop all tables')
