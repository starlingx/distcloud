#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""drop_quota_tables

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-05 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The quotas and quota_classes tables are a leftover from the removed
    # OpenStack quota sync subsystem. Drop them if they exist. They are only
    # present on systems that were deployed before the initial migration
    # stopped creating them.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()
    for table in ("quotas", "quota_classes"):
        if table in existing_tables:
            op.drop_table(table)


def downgrade():
    raise NotImplementedError("Database downgrade is not supported")
