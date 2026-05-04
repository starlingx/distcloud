#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""add indexes

Revision ID: c9911957e77c
Revises: 94f0c5d5bff1
Create Date: 2026-03-23 12:25:30.453819

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9911957e77c"
down_revision: Union[str, None] = "94f0c5d5bff1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("idx_subcloud_name", "subclouds", ["name"])
    op.create_index("idx_subcloud_availability", "subclouds", ["availability_status"])
    op.create_index("idx_subcloud_deploy_status", "subclouds", ["deploy_status"])


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
