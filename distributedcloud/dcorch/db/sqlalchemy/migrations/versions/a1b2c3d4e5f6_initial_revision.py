#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""initial_revision

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-03-31 05:30:00.000000

"""

import datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from oslo_config import cfg

QUOTA_CLASS_NAME_DEFAULT = "default"
CONF = cfg.CONF
CONF.import_group("dc_orch_global_limit", "dcorch.common.config")

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 001_initial: quotas, quota_classes, service
    op.create_table(
        "quotas",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("project_id", sa.String(36)),
        sa.Column("resource", sa.String(255), nullable=False),
        sa.Column("hard_limit", sa.Integer, nullable=False),
        sa.Column("capabilities", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "quota_classes",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("class_name", sa.String(255), index=True),
        sa.Column("capabilities", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Column("resource", sa.String(255)),
        sa.Column("hard_limit", sa.Integer, nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "service",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("host", sa.String(255)),
        sa.Column("binary", sa.String(255)),
        sa.Column("topic", sa.String(255)),
        sa.Column("disabled", sa.Boolean, default=False),
        sa.Column("disabled_reason", sa.String(255)),
        sa.Column("capabilities", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    # Populate quota_classes with defaults
    quota_classes = sa.table(
        "quota_classes",
        sa.column("created_at", sa.DateTime),
        sa.column("class_name", sa.String(255)),
        sa.column("resource", sa.String(255)),
        sa.column("hard_limit", sa.Integer),
        sa.column("deleted", sa.Integer),
    )
    try:
        created_at = datetime.datetime.now()
        for resource, default in CONF.dc_orch_global_limit.items():
            op.execute(
                quota_classes.insert().values(
                    created_at=created_at,
                    class_name=QUOTA_CLASS_NAME_DEFAULT,
                    resource=resource[6:],
                    hard_limit=default,
                    deleted=0,
                )
            )
    except Exception:
        pass

    # 002_orch: subcloud, subcloud_alarms, resource, subcloud_resource,
    #           orch_job, orch_request
    op.create_table(
        "subcloud",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("region_name", sa.String(255), unique=True),
        sa.Column("software_version", sa.String(255)),
        sa.Column("management_state", sa.String(64)),
        sa.Column("availability_status", sa.String(64), default="offline"),
        sa.Column("capabilities", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Index("subcloud_region_name_idx", "region_name"),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "subcloud_alarms",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("region_name", sa.String(255), unique=True),
        sa.Column("critical_alarms", sa.Integer),
        sa.Column("major_alarms", sa.Integer),
        sa.Column("minor_alarms", sa.Integer),
        sa.Column("warnings", sa.Integer),
        sa.Column("cloud_status", sa.String(64)),
        sa.Column("capabilities", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Index("subcloud_alarm_region_name_idx", "region_name"),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "resource",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("resource_type", sa.String(128)),
        sa.Column("master_id", sa.String(255)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Column("capabilities", sa.Text),
        sa.Index("resource_resource_type_idx", "resource_type"),
        sa.Index("resource_master_id_idx", "master_id"),
        sa.UniqueConstraint(
            "resource_type",
            "master_id",
            "deleted",
            name="uniq_resource0resource_type0master_id0deleted",
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "subcloud_resource",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("subcloud_resource_id", sa.String(255)),
        sa.Column("subcloud_name", sa.String(255)),
        sa.Column("shared_config_state", sa.String(64), default="managed"),
        sa.Column("capabilities", sa.Text),
        sa.Column(
            "resource_id",
            sa.Integer,
            sa.ForeignKey("resource.id", ondelete="CASCADE"),
        ),
        sa.Column(
            "subcloud_id",
            sa.Integer,
            sa.ForeignKey("subcloud.id", ondelete="CASCADE"),
        ),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Index("subcloud_resource_resource_id_idx", "resource_id"),
        sa.UniqueConstraint(
            "resource_id",
            "subcloud_id",
            name="uniq_subcloud_resource0resource_id0subcloud_id",
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "orch_job",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("user_id", sa.String(128)),
        sa.Column("project_id", sa.String(128)),
        sa.Column("endpoint_type", sa.String(255), nullable=False),
        sa.Column("source_resource_id", sa.String(255)),
        sa.Column("operation_type", sa.String(255)),
        sa.Column(
            "resource_id",
            sa.Integer,
            sa.ForeignKey("resource.id"),
        ),
        sa.Column("resource_info", sa.Text),
        sa.Column("capabilities", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Index("orch_job_endpoint_type_idx", "endpoint_type"),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    op.create_table(
        "orch_request",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("state", sa.String(128)),
        sa.Column("try_count", sa.Integer, default=0),
        sa.Column("api_version", sa.String(128)),
        sa.Column("target_region_name", sa.String(255)),
        sa.Column("capabilities", sa.Text),
        sa.Column(
            "orch_job_id",
            sa.Integer,
            sa.ForeignKey("orch_job.id"),
        ),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        sa.Index("orch_request_idx", "state"),
        sa.UniqueConstraint(
            "target_region_name",
            "orch_job_id",
            "deleted",
            name="uniq_orchreq0target_region_name0orch_job_id0deleted",
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )


def downgrade():
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
