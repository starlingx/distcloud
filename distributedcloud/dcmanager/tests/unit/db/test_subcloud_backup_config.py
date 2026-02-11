#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy.api import get_session
from dcmanager.db.sqlalchemy import models
from dcmanager.tests import base


class DBAPISubcloudBackupConfig(base.DCManagerTestCase):

    def setUp(self):
        super().setUp()

        # Config table is created by migration script, so we create it manually here
        with db_api.get_engine().begin():
            backup_config = models.SubcloudBackupConfig()
            backup_config.storage_location = consts.BACKUP_STORAGE_DC_VAULT
            backup_config.retention_count = consts.DEFAULT_BACKUP_RETENTION_COUNT
            session = get_session()
            session.add(backup_config)
            session.flush()

    def test_subcloud_backup_config_get(self):
        result = db_api.subcloud_backup_config_get(self.ctx)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, 1)
        self.assertEqual(result.storage_location, consts.BACKUP_STORAGE_DC_VAULT)
        self.assertEqual(result.retention_count, consts.DEFAULT_BACKUP_RETENTION_COUNT)

    def test_subcloud_backup_config_get_not_found(self):
        # Delete the single row to simulate missing config (should never happen)
        engine = db_api.get_engine()
        with engine.begin() as conn:
            conn.execute("DELETE FROM subcloud_backup_config")

        self.assertRaises(
            exception.BackupConfigNotFound,
            db_api.subcloud_backup_config_get,
            self.ctx,
        )

    def test_subcloud_backup_config_update_retention_count(self):
        result = db_api.subcloud_backup_config_update(self.ctx, {"retention_count": 5})
        self.assertEqual(result.retention_count, 5)

        config = db_api.subcloud_backup_config_get(self.ctx)
        self.assertEqual(config.retention_count, 5)

    def test_subcloud_backup_config_update_storage_location(self):
        result = db_api.subcloud_backup_config_update(
            self.ctx, {"storage_location": consts.BACKUP_STORAGE_SEAWEEDFS}
        )
        self.assertEqual(result.storage_location, consts.BACKUP_STORAGE_SEAWEEDFS)

        config = db_api.subcloud_backup_config_get(self.ctx)
        self.assertEqual(config.storage_location, consts.BACKUP_STORAGE_SEAWEEDFS)

    def test_subcloud_backup_config_update_multiple_fields(self):
        result = db_api.subcloud_backup_config_update(
            self.ctx,
            {
                "storage_location": consts.BACKUP_STORAGE_SEAWEEDFS,
                "retention_count": 7,
            },
        )
        self.assertEqual(result.storage_location, consts.BACKUP_STORAGE_SEAWEEDFS)
        self.assertEqual(result.retention_count, 7)

        config = db_api.subcloud_backup_config_get(self.ctx)
        self.assertEqual(config.storage_location, consts.BACKUP_STORAGE_SEAWEEDFS)
        self.assertEqual(config.retention_count, 7)
