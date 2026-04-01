#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""add_subsequent_sync

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-31 05:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from dccommon import consts as dccommon_consts
from dcorch.common import consts

revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "subcloud",
        sa.Column("subsequent_sync", sa.Boolean, default=False),
    )

    subcloud = sa.table(
        "subcloud",
        sa.column("management_state", sa.String(64)),
        sa.column("initial_sync_state", sa.String(64)),
        sa.column("subsequent_sync", sa.Boolean),
    )
    op.execute(
        subcloud.update()
        .where(
            (subcloud.c.management_state == dccommon_consts.MANAGEMENT_MANAGED)
            & (subcloud.c.initial_sync_state == consts.SYNC_STATUS_COMPLETED)
        )
        .values(subsequent_sync=True)
    )


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
