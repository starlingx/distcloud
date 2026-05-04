#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""consolidated_r2509

Revision ID: 94f0c5d5bff1
Revises: 16e1ee6144ad
Create Date: 2026-03-23 12:14:41.112168

"""

from typing import Sequence, Union

from alembic import op
from dccommon import consts as dccommon_consts
from dcmanager.common import consts

import datetime
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "94f0c5d5bff1"
down_revision: Union[str, None] = "16e1ee6144ad"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMNS_TO_RENAME = {
    "compute_apply_type": "worker_apply_type",
    "max_parallel_computes": "max_parallel_workers",
}

ENGINE = ("InnoDB",)
CHARSET = "utf8"


def upgrade():

    # 002_rename_compute_to_worker
    for old_name, new_name in COLUMNS_TO_RENAME.items():
        op.alter_column("sw_update_opts_default", old_name, new_column_name=new_name)
        op.alter_column("sw_update_opts", old_name, new_column_name=new_name)

    # 003_add_deploy_status_column
    op.add_column("subclouds", sa.Column("deploy_status", sa.String(255)))

    # 004_add_openstack_installed_column
    op.add_column(
        "subclouds",
        sa.Column(
            "openstack_installed",
            sa.Boolean,
            nullable=False,
            default=False,
            server_default="0",
        ),
    )

    # 005_add_subcloud_alarms
    op.create_table(
        "subcloud_alarms",
        sa.Column("id", sa.Integer, primary_key=True, nullable=False),
        sa.Column("uuid", sa.String(36), unique=True),
        sa.Column("name", sa.String(255), unique=True),
        sa.Column("critical_alarms", sa.Integer),
        sa.Column("major_alarms", sa.Integer),
        sa.Column("minor_alarms", sa.Integer),
        sa.Column("warnings", sa.Integer),
        sa.Column("cloud_status", sa.String(64)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    # 006_add_subcloud_group_table
    op.create_table(
        "subcloud_group",
        sa.Column(
            "id",
            sa.Integer,
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("name", sa.String(255), unique=True),
        sa.Column("description", sa.String(255)),
        sa.Column("update_apply_type", sa.String(255)),
        sa.Column("max_parallel_subclouds", sa.Integer),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    # Insert default subcloud group
    subcloud_group = sa.table(
        "subcloud_group",
        sa.column("id", sa.Integer),
        sa.column("name", sa.String(255)),
        sa.column("description", sa.String(255)),
        sa.column("update_apply_type", sa.String(255)),
        sa.column("max_parallel_subclouds", sa.Integer),
        sa.column("deleted", sa.Integer),
    )
    op.execute(
        subcloud_group.insert().values(
            id=consts.DEFAULT_SUBCLOUD_GROUP_ID,
            name=consts.DEFAULT_SUBCLOUD_GROUP_NAME,
            description=consts.DEFAULT_SUBCLOUD_GROUP_DESCRIPTION,
            update_apply_type=consts.DEFAULT_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE,
            max_parallel_subclouds=consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS,
            deleted=0,
        )
    )

    # postgres does not increment the subcloud group id sequence
    # after the insert above as part of the migrate.
    bind = op.get_bind()
    if bind.engine.name == "postgresql":
        op.execute("ALTER SEQUENCE subcloud_group_id_seq RESTART WITH 2")

    # Add group_id column to subclouds table
    op.add_column(
        "subclouds",
        sa.Column(
            "group_id",
            sa.Integer,
            server_default=str(consts.DEFAULT_SUBCLOUD_GROUP_ID),
        ),
    )

    if bind.dialect.name != "sqlite":
        op.create_foreign_key(
            "subclouds_group_ref",
            "subclouds",
            "subcloud_group",
            ["group_id"],
            ["id"],
        )

    # 007_add_subcloud_install
    op.add_column("subclouds", sa.Column("data_install", sa.Text))
    op.add_column("subclouds", sa.Column("data_upgrade", sa.Text))

    # 008_add_subcloud_audits_table
    op.create_table(
        "subcloud_audits",
        sa.Column(
            "id", sa.Integer, primary_key=True, autoincrement=True, nullable=False
        ),
        sa.Column(
            "subcloud_id",
            sa.Integer,
            sa.ForeignKey("subclouds.id", ondelete="CASCADE"),
            unique=True,
        ),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer, default=0),
        sa.Column("audit_started_at", sa.DateTime, default=datetime.datetime.min),
        sa.Column("audit_finished_at", sa.DateTime, default=datetime.datetime.min),
        sa.Column("state_update_requested", sa.Boolean, nullable=False, default=False),
        sa.Column("patch_audit_requested", sa.Boolean, nullable=False, default=False),
        sa.Column("load_audit_requested", sa.Boolean, nullable=False, default=False),
        sa.Column(
            "firmware_audit_requested", sa.Boolean, nullable=False, default=False
        ),
        sa.Column(
            "kubernetes_audit_requested", sa.Boolean, nullable=False, default=False
        ),
        sa.Column("spare_audit_requested", sa.Boolean, nullable=False, default=False),
        sa.Column("spare2_audit_requested", sa.Boolean, nullable=False, default=False),
        sa.Column("reserved", sa.Text),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    # Create rows in the new table for each non-deleted subcloud.
    conn = op.get_bind()
    subclouds = sa.table(
        "subclouds",
        sa.column("id", sa.Integer),
        sa.column("deleted", sa.Integer),
    )
    subcloud_audits = sa.table(
        "subcloud_audits",
        sa.column("subcloud_id", sa.Integer),
    )
    subcloud_list = conn.execute(
        subclouds.select().where(subclouds.c.deleted == 0).order_by(subclouds.c.id)
    ).fetchall()
    for subcloud in subcloud_list:
        conn.execute(subcloud_audits.insert().values(subcloud_id=subcloud[0]))

    # 009_add_kube_rootca_audit
    op.add_column(
        "subcloud_audits",
        sa.Column(
            "kube_rootca_update_audit_requested",
            sa.Boolean,
            nullable=False,
            default=False,
            server_default="0",
        ),
    )

    # 010_add_update_extra_args
    op.add_column("sw_update_strategy", sa.Column("extra_args", sa.Text))

    # 011_add_subcloud_backup_columns
    op.add_column("subclouds", sa.Column("backup_status", sa.String(255)))
    op.add_column(
        "subclouds", sa.Column("backup_datetime", sa.DateTime(timezone=False))
    )

    # 012_add_deploy_error_desc_column
    op.add_column(
        "subclouds",
        sa.Column("error_description", sa.String(2048), default="No errors present"),
    )

    # 013_add_subcloud_region_name_column
    op.add_column("subclouds", sa.Column("region_name", sa.String(255)))

    # populates region_name with name field value for existing subclouds
    bind = op.get_bind()
    if bind.engine.name == "postgresql":
        op.execute("UPDATE subclouds SET region_name = name")

    # 014_add_subcloud_peer_group_and_association
    # Add the 'rehome_data' column to the subclouds table.
    op.add_column("subclouds", sa.Column("rehome_data", sa.Text))

    # Create the subcloud_peer_group table
    op.create_table(
        "subcloud_peer_group",
        sa.Column(
            "id",
            sa.Integer,
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("peer_group_name", sa.String(255), unique=True),
        sa.Column("group_priority", sa.Integer),
        sa.Column("group_state", sa.String(255)),
        sa.Column("system_leader_id", sa.String(255)),
        sa.Column("system_leader_name", sa.String(255)),
        sa.Column("max_subcloud_rehoming", sa.Integer),
        sa.Column("migration_status", sa.String(255)),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    # Add the 'peer_group_id' column to the subclouds table.
    op.add_column("subclouds", sa.Column("peer_group_id", sa.Integer))

    # Create the system_peer table
    op.create_table(
        "system_peer",
        sa.Column(
            "id",
            sa.Integer,
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("peer_uuid", sa.String(36), unique=True),
        sa.Column("peer_name", sa.String(255), unique=True),
        sa.Column("manager_endpoint", sa.String(255)),
        sa.Column("manager_username", sa.String(255)),
        sa.Column("manager_password", sa.String(255)),
        sa.Column("peer_controller_gateway_ip", sa.String(255)),
        sa.Column("administrative_state", sa.String(255)),
        sa.Column("heartbeat_interval", sa.Integer),
        sa.Column("heartbeat_failure_threshold", sa.Integer),
        sa.Column("heartbeat_failure_policy", sa.String(255)),
        sa.Column("heartbeat_maintenance_timeout", sa.Integer),
        sa.Column("availability_state", sa.String(255)),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    # Create the peer_group_association table
    op.create_table(
        "peer_group_association",
        sa.Column(
            "id",
            sa.Integer,
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "peer_group_id",
            sa.Integer,
            sa.ForeignKey("subcloud_peer_group.id", ondelete="CASCADE"),
        ),
        sa.Column(
            "system_peer_id",
            sa.Integer,
            sa.ForeignKey("system_peer.id", ondelete="CASCADE"),
        ),
        sa.Column("peer_group_priority", sa.Integer),
        sa.Column("association_type", sa.String(255)),
        sa.Column("sync_status", sa.String(255)),
        sa.Column("sync_message", sa.Text),
        sa.Column("reserved_1", sa.Text),
        sa.Column("reserved_2", sa.Text),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        sa.Column("deleted_at", sa.DateTime),
        sa.Column("deleted", sa.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    # 015_add_subcloud_rehome_flag_column
    op.add_column("subclouds", sa.Column("rehomed", sa.Boolean, default=False))

    # 016_first_identity_sync_complete
    op.add_column(
        "subclouds",
        sa.Column("first_identity_sync_complete", sa.Boolean, default=False),
    )

    # Set the first_identity_sync_complete flag to True for all managed
    # subclouds. This is to ensure that the flag is set to True for all
    # subclouds that have already completed the first identity sync before this.
    subclouds = sa.table(
        "subclouds",
        sa.column("management_state", sa.String(255)),
        sa.column("first_identity_sync_complete", sa.Boolean),
    )
    op.execute(
        subclouds.update()
        .where(subclouds.c.management_state == dccommon_consts.MANAGEMENT_MANAGED)
        .values(first_identity_sync_complete=True)
    )

    # 017_add_subcloud_prestage_columns
    op.add_column("subclouds", sa.Column("prestage_status", sa.String(255)))
    op.add_column("subclouds", sa.Column("prestage_versions", sa.String(255)))

    # Update existing subclouds that have the old prestaging deploy status
    subclouds = sa.table(
        "subclouds",
        sa.column("deploy_status", sa.String(255)),
    )
    op.execute(
        subclouds.update()
        .where(subclouds.c.deploy_status.like("prestage%"))
        .values(deploy_status="complete")
    )

    #  018_add_external_oam_subnet_ip_family_column
    op.add_column(
        "subclouds",
        sa.Column("external_oam_subnet_ip_family", sa.String(255)),
    )

    #  019_resize_strategy_steps_details_column
    with op.batch_alter_table("strategy_steps") as batch_op:
        batch_op.alter_column(
            "details",
            type_=sa.String(1000),
            existing_type=sa.String(255),
        )


def downgrade():
    raise NotImplementedError("Database downgrade is unsupported.")
