#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import rpcapi
from dcmanager.audit import software_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestSoftwareAudit(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._setup_fake_releases()

        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self.mock_regionone_openstackdriver = self._mock_object(
            software_audit, "OpenStackDriver"
        )

        self.mock_regionone_softwareclient = self._mock_object(
            software_audit, "SoftwareClient"
        )
        self.mock_regionone_softwareclient().list.return_value = (
            self.fake_regionone_releases
        )

        self.mock_log = self._mock_object(software_audit, "LOG")

        self.mock_subcloud_softwareclient = mock.MagicMock()

        self.software_audit = software_audit.SoftwareAudit()
        self.audit_manager = subcloud_audit_manager.SubcloudAuditManager()
        self.audit_manager.software_audit = self.software_audit

        self.subcloud = create_fake_subcloud(self.ctx)

    def _create_fake_release(self, release_id, state, sw_version):
        return {"release_id": release_id, "state": state, "sw_version": sw_version}

    def _setup_fake_releases(self):
        self.fake_regionone_releases = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release("starlingx-9.0.2", "available", "9.0.2"),
        ]

        self.fake_in_sync_releases = [
            self._create_fake_release("starlingx-8.0.3", "unavailable", "9.0.2"),
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release("starlingx-9.0.2", "available", "9.0.2"),
        ]

    def _get_software_audit_data(self):
        (_, _, _, software_audit_data) = self.audit_manager._get_audit_data(
            False, False, False, True
        )

        # Convert to dict like what would happen calling via RPC
        if software_audit_data:
            return software_audit_data.to_dict()
        return software_audit_data

    def _test_software_audit(self, sync_status, software_version):
        response = self.software_audit.get_subcloud_sync_status(
            self.mock_subcloud_softwareclient,
            self._get_software_audit_data(),
            self.subcloud.name,
        )

        self.assertEqual(response.get("sync_status"), sync_status)
        self.assertEqual(response.get("software_version"), software_version)

    def test_software_audit_in_sync(self):
        self.mock_subcloud_softwareclient.list.return_value = self.fake_in_sync_releases

        self._test_software_audit(dccommon_consts.SYNC_STATUS_IN_SYNC, "9.0")

    def test_software_audit_empty_audit_data(self):
        response = self.software_audit.get_subcloud_sync_status(
            self.mock_subcloud_softwareclient,
            None,
            self.subcloud.name,
        )

        self.assertEqual(
            response.get("sync_status"), dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        self.assertEqual(response.get("software_version"), None)

    def test_software_audit_skip_audit_on_exception(self):
        self.mock_subcloud_softwareclient.list.side_effect = Exception("fake")

        response = self.software_audit.get_subcloud_sync_status(
            self.mock_subcloud_softwareclient,
            self._get_software_audit_data(),
            self.subcloud.name,
        )

        self.assertIsNone(response)
        self.mock_log.warn.assert_called_with(
            "Cannot retrieve subcloud releases, skip software audit."
        )

    def test_software_audit_region_one_client_creation_exception(self):
        self.mock_regionone_softwareclient.side_effect = Exception("fake")

        response = self._get_software_audit_data()

        self.assertIsNone(response)
        self.mock_log.exception.assert_called_with(
            "Failure initializing OS Client, skip software audit."
        )
