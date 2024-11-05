#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table, Index

# Index names
SUBCLOUD_STATUS_IDX_NAME = "subcloud_status_subcloud_id_idx"
SUBCLOUDS_REGION_IDX_NAME = "subclouds_region_name_idx"


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Load tables
    subcloud_status = Table("subcloud_status", meta, autoload=True)
    subclouds = Table("subclouds", meta, autoload=True)

    # Create new indexes
    index = Index(SUBCLOUD_STATUS_IDX_NAME, subcloud_status.c.subcloud_id)
    index.create(migrate_engine)

    index = Index(SUBCLOUDS_REGION_IDX_NAME, subclouds.c.region_name)
    index.create(migrate_engine)


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
