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

import sqlalchemy

from dccommon import consts as dccommon_consts


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine
    subcloud = sqlalchemy.Table("subclouds", meta, autoload=True)

    # Add the first_identity_sync_complete column
    subcloud.create_column(
        sqlalchemy.Column(
            "first_identity_sync_complete", sqlalchemy.Boolean, default=False
        )
    )

    # NOTE(nicodemos): Set the first_identity_sync_complete flag to True for all
    # managed subclouds. This is to ensure that the flag is set to True for all
    # subclouds that have already completed the first identity sync before this.
    # pylint: disable-next=E1120
    subcloud.update().where(
        (subcloud.c.management_state == dccommon_consts.MANAGEMENT_MANAGED)
    ).values({"first_identity_sync_complete": True}).execute()


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
