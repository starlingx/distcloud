#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from keystoneauth1 import exceptions as keystone_exceptions
import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import rpcapi
from dcmanager.audit import software_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud

FAKE_REGIONONE_RELEASES = [
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.1",
        "state": "deployed",
        "sw_version": "9.0.1",
    },
    {
        "release_id": "starlingx-9.0.2",
        "state": "available",
        "sw_version": "9.0.2",
    },
]

FAKE_SUBCLOUD_RELEASES_IN_SYNC = [
    {
        "release_id": "starlingx-8.0.3",
        "state": "unavailable",
        "sw_version": "9.0.2",
    },
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.1",
        "state": "deployed",
        "sw_version": "9.0.1",
    },
    {
        "release_id": "starlingx-9.0.2",
        "state": "available",
        "sw_version": "9.0.2",
    },
]

FAKE_SUBCLOUD_RELEASES_MISSING_OUT_OF_SYNC = [
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.1",
        "state": "available",
        "sw_version": "9.0.1",
    },
]

FAKE_SUBCLOUD_RELEASES_EXTRA_OUT_OF_SYNC = [
    {
        "release_id": "starlingx-9.0.0",
        "state": "deployed",
        "sw_version": "9.0.0",
    },
    {
        "release_id": "starlingx-9.0.2",
        "state": "deployed",
        "sw_version": "9.0.2",
    },
    {
        "release_id": "starlingx-9.0.3",
        "state": "deployed",
        "sw_version": "9.0.3",
    },
]


class TestSoftwareAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self.mock_software_client = self._mock_object(software_audit, "SoftwareClient")
        self._mock_object(software_audit, "OpenStackDriver")

        self.software_audit = software_audit.SoftwareAudit()
        self.audit_manager = subcloud_audit_manager.SubcloudAuditManager()
        self.audit_manager.software_audit = self.software_audit

        self.keystone_client = mock.MagicMock()

        # Mock RegionOne SoftwareClient's list method
        regionone_software_client = self.mock_software_client.return_value
        regionone_software_client.list.return_value = FAKE_REGIONONE_RELEASES

    def get_software_audit_data(self):
        (_, _, _, _, software_audit_data) = self.audit_manager._get_audit_data(
            False, False, False, False, True
        )
        # Convert to dict like what would happen calling via RPC
        software_audit_data = software_audit_data.to_dict()
        return software_audit_data

    def test_software_audit_previous_release_not_usm(self):
        software_audit_data = self.get_software_audit_data()
        subcloud = create_fake_subcloud(self.ctx)
        self.keystone_client.services.find.side_effect = keystone_exceptions.NotFound
        software_response = self.software_audit.subcloud_software_audit(
            self.keystone_client,
            subcloud,
            software_audit_data,
        )
        expected_software_response = dccommon_consts.SYNC_STATUS_NOT_AVAILABLE
        self.assertEqual(software_response, expected_software_response)

    def test_software_audit_previous_release_usm(self):
        software_audit_data = self.get_software_audit_data()
        subcloud = create_fake_subcloud(self.ctx)

        sc_software_client = self.mock_software_client(subcloud.region_name)
        sc_software_client.list.return_value = (
            FAKE_SUBCLOUD_RELEASES_MISSING_OUT_OF_SYNC
        )
        software_response = self.software_audit.subcloud_software_audit(
            self.keystone_client,
            subcloud,
            software_audit_data,
        )

        expected_software_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        self.assertEqual(
            software_response.get("sync_status"), expected_software_response
        )
        expected_software_version = "9.0"
        self.assertEqual(
            software_response.get("software_version"), expected_software_version
        )

    def test_software_audit_in_sync(self):
        software_audit_data = self.get_software_audit_data()
        subcloud = create_fake_subcloud(self.ctx, software_version="TEST.SW.VERSION")

        sc_software_client = self.mock_software_client(subcloud.region_name)
        sc_software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_IN_SYNC
        software_response = self.software_audit.subcloud_software_audit(
            self.keystone_client,
            subcloud,
            software_audit_data,
        )

        expected_software_response = dccommon_consts.SYNC_STATUS_IN_SYNC
        self.assertEqual(
            software_response.get("sync_status"), expected_software_response
        )
        expected_software_version = "9.0"
        self.assertEqual(
            software_response.get("software_version"), expected_software_version
        )

    def test_software_audit_missing_release_out_of_sync(self):
        software_audit_data = self.get_software_audit_data()
        subcloud = create_fake_subcloud(self.ctx, software_version="TEST.SW.VERSION")

        sc_software_client = self.mock_software_client(subcloud.region_name)
        sc_software_client.list.return_value = (
            FAKE_SUBCLOUD_RELEASES_MISSING_OUT_OF_SYNC
        )
        software_response = self.software_audit.subcloud_software_audit(
            self.keystone_client,
            subcloud,
            software_audit_data,
        )

        expected_software_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        self.assertEqual(
            software_response.get("sync_status"), expected_software_response
        )
        expected_software_version = "9.0"
        self.assertEqual(
            software_response.get("software_version"), expected_software_version
        )

    def test_software_audit_extra_release_out_of_sync(self):
        software_audit_data = self.get_software_audit_data()
        subcloud = create_fake_subcloud(self.ctx, software_version="TEST.SW.VERSION")

        sc_software_client = self.mock_software_client(subcloud.region_name)
        sc_software_client.list.return_value = FAKE_SUBCLOUD_RELEASES_EXTRA_OUT_OF_SYNC
        software_response = self.software_audit.subcloud_software_audit(
            self.keystone_client,
            subcloud,
            software_audit_data,
        )

        expected_software_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        self.assertEqual(
            software_response.get("sync_status"), expected_software_response
        )
        expected_software_version = "9.0"
        self.assertEqual(
            software_response.get("software_version"), expected_software_version
        )
