#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sqlalchemy

from dccommon import consts as dccommon_consts
from dcorch.common import consts


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    subcloud = sqlalchemy.Table("subcloud", meta, autoload=True)

    # Add the subsequent_sync attribute
    subcloud.create_column(
        sqlalchemy.Column(
            "subsequent_sync",
            sqlalchemy.Boolean,
            default=False,
        )
    )

    # pylint: disable-next=E1120
    subcloud.update().where(
        (subcloud.c.management_state == dccommon_consts.MANAGEMENT_MANAGED)
        & (subcloud.c.initial_sync_state == consts.SYNC_STATUS_COMPLETED)
    ).values({"subsequent_sync": True}).execute()

    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
