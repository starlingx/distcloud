#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""add_software_audit_column

Revision ID: 65c98c626672
Revises: dcede6b55883
Create Date: 2026-03-23 12:33:18.439095

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "65c98c626672"
down_revision: Union[str, None] = "dcede6b55883"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "subcloud_audits",
        sa.Column(
            "software_audit_requested",
            sa.Boolean,
            nullable=False,
            server_default="false",
        ),
    )

    subcloud_audits = sa.table(
        "subcloud_audits",
        sa.column("software_audit_requested", sa.Boolean),
        sa.column("spare_audit_requested", sa.Boolean),
    )
    op.execute(
        subcloud_audits.update().values(
            software_audit_requested=subcloud_audits.c.spare_audit_requested
        )
    )
    op.execute(subcloud_audits.update().values(spare_audit_requested=False))


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
