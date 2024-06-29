# Copyright (c) 2023-2024 Wind River Systems, Inc.
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

    # Add the 'region_name' column to the subclouds table.
    subclouds.create_column(Column("region_name", String(255)))

    # populates region_name with name field value for existing subclouds
    if migrate_engine.name == "postgresql":
        with migrate_engine.begin() as conn:
            conn.execute("UPDATE subclouds SET region_name = name")

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
