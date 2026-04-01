#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""consolidated_r2509

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-31 05:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 003_initial_sync: add initial_sync_state to subcloud
    op.add_column(
        "subcloud",
        sa.Column("initial_sync_state", sa.String(64), default="none"),
    )

    # 004_delete_subcloud_alarms: drop subcloud_alarms table
    op.drop_table("subcloud_alarms")

    # 005_add_indices: add indices to orch_request
    op.create_index(
        "orch_request_updated_at_state_idx",
        "orch_request",
        ["updated_at", "state"],
    )
    op.create_index(
        "orch_request_deleted_at_idx",
        "orch_request",
        ["deleted_at"],
    )
    op.create_index(
        "orch_request_orch_job_id_idx",
        "orch_request",
        ["orch_job_id"],
    )

    # 006_sync_lock: create sync_lock table
    op.create_table(
        "sync_lock",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("subcloud_name", sa.String(255), nullable=False),
        sa.Column("endpoint_type", sa.String(255)),
        sa.Column("engine_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.UniqueConstraint(
            "subcloud_name",
            "endpoint_type",
            "action",
            name="uniq_sync_lock0subcloud_name0endpoint_type0action",
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    # 007_subcloud_sync: create subcloud_sync table
    op.create_table(
        "subcloud_sync",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column(
            "subcloud_id",
            sa.Integer,
            sa.ForeignKey("subcloud.id", ondelete="CASCADE"),
        ),
        sa.Column("subcloud_name", sa.String(255)),
        sa.Column("endpoint_type", sa.String(255), default="none"),
        sa.Column("sync_request", sa.String(64), default="none"),
        sa.Column("sync_status_reported", sa.String(64), default="none"),
        sa.Column("sync_status_report_time", sa.DateTime),
        sa.Column("audit_status", sa.String(64), default="none"),
        sa.Column("last_audit_time", sa.DateTime),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Index(
            "subcloud_sync_subcloud_name_endpoint_type_idx",
            "subcloud_name",
            "endpoint_type",
        ),
        sa.UniqueConstraint(
            "subcloud_name",
            "endpoint_type",
            name="uniq_subcloud_sync0subcloud_name0endpoint_type",
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    # 008_delete_sync_lock: drop sync_lock table
    op.drop_table("sync_lock")


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
