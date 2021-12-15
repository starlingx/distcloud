# Copyright (c) 2021 Wind River Systems, Inc.
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

import datetime
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import Text


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subclouds = Table('subclouds', meta, autoload=True)
    subcloud_audits = Table(
        'subcloud_audits', meta,
        Column('id', Integer, primary_key=True,
               autoincrement=True, nullable=False),
        Column('subcloud_id', Integer,
               ForeignKey('subclouds.id', ondelete='CASCADE'),
               unique=True),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Integer, default=0),
        Column('audit_started_at', DateTime, default=datetime.datetime.min),
        Column('audit_finished_at', DateTime, default=datetime.datetime.min),
        Column('state_update_requested', Boolean, nullable=False, default=False),
        Column('patch_audit_requested', Boolean, nullable=False, default=False),
        Column('load_audit_requested', Boolean, nullable=False, default=False),
        Column('firmware_audit_requested', Boolean, nullable=False, default=False),
        Column('kubernetes_audit_requested', Boolean, nullable=False, default=False),
        Column('spare_audit_requested', Boolean, nullable=False, default=False),
        Column('spare2_audit_requested', Boolean, nullable=False, default=False),
        Column('reserved', Text),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )
    subcloud_audits.create()

    # Create rows in the new table for each non-deleted subcloud.
    subcloud_list = list(subclouds.select().where(subclouds.c.deleted == 0)
                         .order_by(subclouds.c.id).execute())
    for subcloud in subcloud_list:
        subcloud_audits.insert().execute({'subcloud_id': subcloud['id']})  # pylint: disable=no-value-for-parameter


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
