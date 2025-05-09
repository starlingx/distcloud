#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import datetime
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import Text


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subcloud_audits = Table("subcloud_audits", meta, autoload=True)

    # The unit tests will use sqlite as the migration engine, but it is not capable
    # of properly handling the column drop for NOT NULL columns, requiring the whole
    # table to be recreated.
    if migrate_engine.name == "sqlite":
        subcloud_audits.drop()

        # Temporarily create the subcloud_audits table with another name
        new_subcloud_audits = Table(
            "new_subcloud_audits",
            meta,
            Column("id", Integer, primary_key=True, autoincrement=True, nullable=False),
            Column(
                "subcloud_id",
                Integer,
                ForeignKey("subclouds.id", ondelete="CASCADE"),
                unique=True,
            ),
            Column("created_at", DateTime),
            Column("updated_at", DateTime),
            Column("deleted_at", DateTime),
            Column("deleted", Integer, default=0),
            Column("audit_started_at", DateTime, default=datetime.datetime.min),
            Column("audit_finished_at", DateTime, default=datetime.datetime.min),
            Column("state_update_requested", Boolean, nullable=False, default=False),
            Column("firmware_audit_requested", Boolean, nullable=False, default=False),
            Column(
                "kubernetes_audit_requested", Boolean, nullable=False, default=False
            ),
            Column("spare_audit_requested", Boolean, nullable=False, default=False),
            Column("spare2_audit_requested", Boolean, nullable=False, default=False),
            Column("reserved", Text),
            Column(
                "kube_rootca_update_audit_requested",
                Boolean,
                nullable=False,
                default=False,
                server_default="0",
            ),
            mysql_engine="InnoDB",
            mysql_charset="utf8",
        )
        new_subcloud_audits.create()

        # Update the table name
        new_subcloud_audits.rename("subcloud_audits")

    else:
        subcloud_audits.drop_column("patch_audit_requested")
        subcloud_audits.drop_column("load_audit_requested")

    subcloud_status = Table("subcloud_status", meta, autoload=True)
    subcloud_status.delete().where(  # pylint: disable=E1120
        subcloud_status.c.endpoint_type.in_(["patching", "load"])
    ).execute()


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
