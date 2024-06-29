#
# Copyright (c) 2021, 2024 Wind River Systems, Inc.
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

    # Add the kube_rootca_update_audit_requested  column to the audits table.
    subcloud_audits.create_column(
        Column(
            "kube_rootca_update_audit_requested",
            Boolean,
            nullable=False,
            default=False,
            server_default="0",
        )
    )
    return True


def downgrade(migrate_engine):
    raise NotImplementedError("Database downgrade is unsupported.")
