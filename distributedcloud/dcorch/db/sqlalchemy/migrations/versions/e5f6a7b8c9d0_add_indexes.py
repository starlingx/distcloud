#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""add_indexes

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-03-31 05:30:00.000000

"""

from typing import Sequence, Union

from alembic import op

revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "subcloud_resource_subcloud_id_idx",
        "subcloud_resource",
        ["resource_id", "subcloud_id"],
    )
    op.create_index(
        "subcloud_resource_resource_id_subcloud_id_idx",
        "subcloud_resource",
        ["subcloud_id"],
    )
    op.create_index(
        "subcloud_sync_subcloud_name_idx",
        "subcloud_sync",
        ["subcloud_name"],
    )


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
