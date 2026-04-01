#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""initial_revision

Revision ID: 16e1ee6144ad
Revises:
Create Date: 2026-03-23 12:12:43.433614

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "16e1ee6144ad"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.create_table(
        "subclouds",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("name", sa.String(255), unique=True),
        sa.Column("description", sa.String(255)),
        sa.Column("location", sa.String(255)),
        sa.Column("software_version", sa.String(255)),
        sa.Column("management_state", sa.String(255)),
        sa.Column("availability_status", sa.String(255)),
        sa.Column("management_subnet", sa.String(255)),
        sa.Column("management_gateway_ip", sa.String(255)),
        sa.Column("management_start_ip", sa.String(255)),
        sa.Column("management_end_ip", sa.String(255)),
        sa.Column("systemcontroller_gateway_ip", sa.String(255)),
        sa.Column("audit_fail_count", sa.Integer, default=0),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "subcloud_status",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column(
            "subcloud_id",
            sa.Integer,
            sa.ForeignKey("subclouds.id", ondelete="CASCADE"),
        ),
        sa.Column("endpoint_type", sa.String(255)),
        sa.Column("sync_status", sa.String(255)),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "sw_update_strategy",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("type", sa.String(255), unique=True),
        sa.Column("subcloud_apply_type", sa.String(255)),
        sa.Column("max_parallel_subclouds", sa.Integer),
        sa.Column("stop_on_failure", sa.Boolean),
        sa.Column("state", sa.String(255)),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "strategy_steps",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column(
            "subcloud_id",
            sa.Integer,
            sa.ForeignKey("subclouds.id", ondelete="CASCADE"),
            unique=True,
        ),
        sa.Column("stage", sa.Integer),
        sa.Column("state", sa.String(255)),
        sa.Column("details", sa.String(255)),
        sa.Column("started_at", sa.DateTime),
        sa.Column("finished_at", sa.DateTime),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "sw_update_opts",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column(
            "subcloud_id",
            sa.Integer,
            sa.ForeignKey("subclouds.id", ondelete="CASCADE"),
        ),
        sa.Column("storage_apply_type", sa.String(255)),
        sa.Column("compute_apply_type", sa.String(255)),
        sa.Column("max_parallel_computes", sa.Integer),
        sa.Column("default_instance_action", sa.String(255)),
        sa.Column("alarm_restriction_type", sa.String(255)),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "sw_update_opts_default",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("subcloud_id", sa.Integer),
        sa.Column("storage_apply_type", sa.String(255)),
        sa.Column("compute_apply_type", sa.String(255)),
        sa.Column("max_parallel_computes", sa.Integer),
        sa.Column("default_instance_action", sa.String(255)),
        sa.Column("alarm_restriction_type", sa.String(255)),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    # Populate sw_update_opts_default with default values
    sw_update_opts_default = sa.table(
        "sw_update_opts_default",
        sa.column("storage_apply_type", sa.String(255)),
        sa.column("compute_apply_type", sa.String(255)),
        sa.column("max_parallel_computes", sa.Integer),
        sa.column("default_instance_action", sa.String(255)),
        sa.column("alarm_restriction_type", sa.String(255)),
        sa.column("deleted", sa.Integer),
    )
    try:
        op.execute(
            sw_update_opts_default.insert().values(
                storage_apply_type="parallel",
                compute_apply_type="parallel",
                max_parallel_computes=10,
                default_instance_action="migrate",
                alarm_restriction_type="relaxed",
                deleted=0,
            )
        )
    except Exception:
        pass


def downgrade():
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
