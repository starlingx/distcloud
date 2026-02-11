#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_db import exception as db_exception

from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.db import api as db_api
from dcmanager.tests import base


class DBAPISubcloudBackupArchive(base.DCManagerTestCase):

    def setUp(self):
        super().setUp()
        # Create a subcloud to satisfy the foreign key constraint
        self.subcloud = db_api.subcloud_create(
            self.ctx,
            name="subcloud1",
            description="test subcloud",
            location="test location",
            software_version="26.03",
            management_subnet="192.168.101.0/24",
            management_gateway_ip="192.168.101.1",
            management_start_ip="192.168.101.2",
            management_end_ip="192.168.101.50",
            systemcontroller_gateway_ip="192.168.204.101",
            external_oam_subnet_ip_family="4",
            deploy_status="not-deployed",
            error_description="No errors present",
            region_name="2ec93dfb654846909efe61d1b39dd2ce",
            openstack_installed=False,
            group_id=1,
            data_install="data from install",
        )

    def create_backup_archive(
        self,
        subcloud_id=None,
        backup_id="subcloud1-26.03-202602041930",
        release_version="26.03",
        storage_location=consts.BACKUP_STORAGE_DC_VAULT,
        storage_path="/opt/dc-vault/backups/subcloud1/26.03/"
        "subcloud1_platform_backup_2026_02_04_19_30_25.tgz",
        size_bytes=1024,
    ):
        subcloud_id = subcloud_id or self.subcloud.id

        return db_api.subcloud_backup_archive_create(
            self.ctx,
            backup_id=backup_id,
            subcloud_id=subcloud_id,
            release_version=release_version,
            storage_location=storage_location,
            storage_path=storage_path,
            size_bytes=size_bytes,
        )

    def test_subcloud_backup_archive_create(self):
        result = self.create_backup_archive()
        self.assertIsNotNone(result)
        self.assertEqual(result.backup_id, "subcloud1-26.03-202602041930")
        self.assertEqual(result.subcloud_id, self.subcloud.id)
        self.assertEqual(result.release_version, "26.03")
        self.assertEqual(result.storage_location, consts.BACKUP_STORAGE_DC_VAULT)
        self.assertEqual(result.size_bytes, 1024)

    def test_subcloud_backup_archive_create_duplicate_backup_id(self):
        self.create_backup_archive()
        self.assertRaises(db_exception.DBDuplicateEntry, self.create_backup_archive)

    def test_subcloud_backup_archive_get_all(self):
        self.create_backup_archive(backup_id="backup-1")
        self.create_backup_archive(backup_id="backup-2")
        archives = db_api.subcloud_backup_archive_get_all(self.ctx)
        self.assertEqual(len(archives), 2)

    def test_subcloud_backup_archive_get_all_empty(self):
        archives = db_api.subcloud_backup_archive_get_all(self.ctx)
        self.assertEqual(len(archives), 0)

    def test_subcloud_backup_archive_get_all_filter_by_subcloud(self):
        subcloud2 = db_api.subcloud_create(
            self.ctx,
            name="subcloud2",
            description="test subcloud 2",
            location="test location",
            software_version="26.03",
            management_subnet="192.168.102.0/24",
            management_gateway_ip="192.168.102.1",
            management_start_ip="192.168.102.2",
            management_end_ip="192.168.102.50",
            systemcontroller_gateway_ip="192.168.204.102",
            external_oam_subnet_ip_family="4",
            deploy_status="not-deployed",
            error_description="No errors present",
            region_name="3ec93dfb654846909efe61d1b39dd2cf",
            openstack_installed=False,
            group_id=1,
            data_install="data from install",
        )
        self.create_backup_archive(backup_id="backup-sc1")
        self.create_backup_archive(subcloud_id=subcloud2.id, backup_id="backup-sc2")

        archives = db_api.subcloud_backup_archive_get_all(
            self.ctx, subcloud_ids=[self.subcloud.id]
        )
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].backup_id, "backup-sc1")

    def test_subcloud_backup_archive_get_all_filter_by_release(self):
        self.create_backup_archive(backup_id="backup-v26", release_version="26.03")
        self.create_backup_archive(backup_id="backup-v25", release_version="25.09")

        archives = db_api.subcloud_backup_archive_get_all(
            self.ctx, release_version="26.03"
        )
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].backup_id, "backup-v26")

    def test_subcloud_backup_archive_get_all_filter_by_storage_location(self):
        self.create_backup_archive(
            backup_id="backup-vault", storage_location=consts.BACKUP_STORAGE_DC_VAULT
        )
        self.create_backup_archive(
            backup_id="backup-seaweed",
            storage_location=consts.BACKUP_STORAGE_SEAWEEDFS,
        )

        archives = db_api.subcloud_backup_archive_get_all(
            self.ctx, storage_location=consts.BACKUP_STORAGE_DC_VAULT
        )
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].backup_id, "backup-vault")

    def test_subcloud_backup_archive_get_all_order_ascending(self):
        self.create_backup_archive(backup_id="backup-1")
        self.create_backup_archive(backup_id="backup-2")

        archives = db_api.subcloud_backup_archive_get_all(
            self.ctx, order_by="created_at", order_desc=False
        )
        self.assertEqual(len(archives), 2)
        # First created should come first when ascending
        self.assertEqual(archives[0].backup_id, "backup-1")
        self.assertEqual(archives[1].backup_id, "backup-2")

    def test_subcloud_backup_archive_delete(self):
        backup_id = "subcloud1-26.03-202602041930"
        self.create_backup_archive(backup_id=backup_id)

        archives = db_api.subcloud_backup_archive_get_all(self.ctx)
        self.assertEqual(len(archives), 1)

        db_api.subcloud_backup_archive_delete(self.ctx, backup_id)

        archives = db_api.subcloud_backup_archive_get_all(self.ctx)
        self.assertEqual(len(archives), 0)

    def test_subcloud_backup_archive_delete_not_found(self):
        self.assertRaises(
            exception.BackupArchiveNotFound,
            db_api.subcloud_backup_archive_delete,
            self.ctx,
            "nonexistent-backup-id",
        )
