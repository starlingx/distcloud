# Copyright (c) 2020-2021 Wind River Systems, Inc.
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

import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    subcloud_alarms = sqlalchemy.Table(
        'subcloud_alarms', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True, nullable=False),
        sqlalchemy.Column('uuid', sqlalchemy.String(36), unique=True),

        sqlalchemy.Column('name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('critical_alarms', sqlalchemy.Integer),
        sqlalchemy.Column('major_alarms', sqlalchemy.Integer),
        sqlalchemy.Column('minor_alarms', sqlalchemy.Integer),
        sqlalchemy.Column('warnings', sqlalchemy.Integer),
        sqlalchemy.Column('cloud_status', sqlalchemy.String(64)),

        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer),

        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    subcloud_alarms.create()


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade not supported - '
                              'would drop all tables')
