#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
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
        self._mock_object(EndpointCache, "get_admin_session")

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

    def _create_fake_release(self, release_id, state, sw_version, metapackages=None):
        release = {
            "release_id": release_id,
            "state": state,
            "sw_version": sw_version,
        }
        if metapackages is not None:
            release["metapackages"] = metapackages
        return release

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

    def test_software_audit_deployed_partial_in_sync(self):
        """Same metapackages deployed on RegionOne and subcloud -> in-sync."""
        metapackages = {
            "infra_9.0.2": {"state": "deployed"},
            "distcloud_9.0.2": {"state": "available"},
        }
        self.mock_regionone_softwareclient().list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", metapackages
            ),
        ]
        self.mock_subcloud_softwareclient.list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", metapackages
            ),
        ]

        self._test_software_audit(dccommon_consts.SYNC_STATUS_IN_SYNC, "9.0")

    def test_software_audit_deployed_partial_metapackages_differ(self):
        """Different deployed metapackages -> out-of-sync."""
        central_metapackages = {
            "infra_9.0.2": {"state": "deployed"},
            "distcloud_9.0.2": {"state": "deployed"},
        }
        subcloud_metapackages = {
            "infra_9.0.2": {"state": "deployed"},
            "distcloud_9.0.2": {"state": "available"},
        }
        self.mock_regionone_softwareclient().list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", central_metapackages
            ),
        ]
        self.mock_subcloud_softwareclient.list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", subcloud_metapackages
            ),
        ]

        self._test_software_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, "9.0")

    def test_software_audit_deployed_partial_vs_deployed(self):
        """Deployed-partial on RegionOne, fully deployed on subcloud ->

        out-of-sync, since the subcloud has no deployed metapackages to match.
        """
        central_metapackages = {
            "infra_9.0.2": {"state": "deployed"},
            "distcloud_9.0.2": {"state": "available"},
        }
        self.mock_regionone_softwareclient().list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", central_metapackages
            ),
        ]
        self.mock_subcloud_softwareclient.list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release("starlingx-9.0.2", "deployed", "9.0.2"),
        ]

        self._test_software_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, "9.0")

    def test_software_audit_subcloud_no_metapackage_deployed(self):
        """Subcloud returns no metapackage deployed -> out-of-sync.

        RegionOne has metapackages deployed in the deployed-partial release
        while the subcloud has the same release in deployed-partial but with
        none of its metapackages deployed.
        """
        central_metapackages = {
            "infra_9.0.2": {"state": "deployed"},
            "distcloud_9.0.2": {"state": "deployed"},
        }
        subcloud_metapackages = {
            "infra_9.0.2": {"state": "available"},
            "distcloud_9.0.2": {"state": "available"},
        }
        self.mock_regionone_softwareclient().list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", central_metapackages
            ),
        ]
        self.mock_subcloud_softwareclient.list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", subcloud_metapackages
            ),
        ]

        self._test_software_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, "9.0")

    def test_software_audit_deployed_vs_deployed_partial(self):
        """System controller deployed, subcloud deployed-partial ->

        out-of-sync, since the subcloud has deployed metapackages that the
        system controller does not.
        """
        subcloud_metapackages = {
            "infra_9.0.2": {"state": "deployed"},
            "distcloud_9.0.2": {"state": "available"},
        }
        self.mock_regionone_softwareclient().list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release("starlingx-9.0.2", "deployed", "9.0.2"),
        ]
        self.mock_subcloud_softwareclient.list.return_value = [
            self._create_fake_release("starlingx-9.0.0", "deployed", "9.0.0"),
            self._create_fake_release("starlingx-9.0.1", "deployed", "9.0.1"),
            self._create_fake_release(
                "starlingx-9.0.2", "deployed-partial", "9.0.2", subcloud_metapackages
            ),
        ]

        self._test_software_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, "9.0")
