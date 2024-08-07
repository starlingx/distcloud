# Copyright (c) 2019-2021, 2024 Wind River Systems, Inc.
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

from sqlalchemy import Column, MetaData, String, Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subclouds = Table("subclouds", meta, autoload=True)

    # Add the 'deploy_status' column to the subclouds table.
    subclouds.create_column(Column("deploy_status", String(255)))

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
