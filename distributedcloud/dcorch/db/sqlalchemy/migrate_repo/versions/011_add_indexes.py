#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table, Index

# Index names
SUBCLOUD_RESOURCE_IDX_NAME = "subcloud_resource_subcloud_id_idx"
SUBCLOUD_RESOURCE_COMPOSITE_IDX_NAME = "subcloud_resource_resource_id_subcloud_id_idx"
SUBCLOUD_SYNC_IDX_NAME = "subcloud_sync_subcloud_name_idx"


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Load tables
    subcloud_resource = Table("subcloud_resource", meta, autoload=True)
    subcloud_sync = Table("subcloud_sync", meta, autoload=True)

    # Create new indexes
    index = Index(
        SUBCLOUD_RESOURCE_IDX_NAME,
        subcloud_resource.c.resource_id,
        subcloud_resource.c.subcloud_id,
    )
    index.create(migrate_engine)

    index = Index(
        SUBCLOUD_RESOURCE_COMPOSITE_IDX_NAME,
        subcloud_resource.c.subcloud_id,
    )
    index.create(migrate_engine)

    index = Index(SUBCLOUD_SYNC_IDX_NAME, subcloud_sync.c.subcloud_name)
    index.create(migrate_engine)


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
