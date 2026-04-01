#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""remove_patch_and_load_audits_column

Revision ID: dcede6b55883
Revises: c9911957e77c
Create Date: 2026-03-23 12:27:10.238413

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "dcede6b55883"
down_revision: Union[str, None] = "c9911957e77c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("subcloud_audits") as batch_op:
        batch_op.drop_column("patch_audit_requested")
        batch_op.drop_column("load_audit_requested")

    subcloud_status = sa.table(
        "subcloud_status",
        sa.column("endpoint_type", sa.String(255)),
    )
    op.execute(
        subcloud_status.delete().where(
            subcloud_status.c.endpoint_type.in_(["patching", "load"])
        )
    )


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
