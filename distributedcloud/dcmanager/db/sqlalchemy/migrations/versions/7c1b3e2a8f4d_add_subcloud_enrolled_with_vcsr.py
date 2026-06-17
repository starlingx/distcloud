#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""add_subcloud_enrolled_with_vcsr

Revision ID: 7c1b3e2a8f4d
Revises: 65c98c626672
Create Date: 2026-06-11 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "7c1b3e2a8f4d"
down_revision: Union[str, None] = "65c98c626672"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "subclouds",
        sa.Column(
            "enrolled_with_vcsr",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
    )


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
