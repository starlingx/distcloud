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
# Copyright (c) 2019 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from sqlalchemy import Column, MetaData, Table, Boolean


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subclouds = Table('subclouds', meta, autoload=True)

    # Add the 'openstack_installed' column to the subclouds table.
    subclouds.create_column(Column('openstack_installed', Boolean,
                                   nullable=False, default=False,
                                   server_default='0'))

    return True


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
