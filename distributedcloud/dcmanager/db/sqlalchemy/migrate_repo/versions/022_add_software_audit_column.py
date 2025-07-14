#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    subcloud_audits = Table("subcloud_audits", meta, autoload=True)
    subcloud_audits.create_column(
        Column("software_audit_requested", Boolean, default=False)
    )

    # Replaces the data from spare_audit_requested to software_audit_requested
    if migrate_engine.name == "postgresql":
        subcloud_audits.update().values(  # pylint: disable=E1120
            {"software_audit_requested": subcloud_audits.c.spare_audit_requested}
        ).execute()
        # Reset the spare_audit_requested column to its default value
        subcloud_audits.update().values(  # pylint: disable=E1120
            {"spare_audit_requested": False}
        ).execute()

    subcloud_audits.c.software_audit_requested.alter(nullable=False)


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
