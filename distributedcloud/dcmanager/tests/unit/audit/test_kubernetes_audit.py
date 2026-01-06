# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from uuid import uuid4

import mock

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


PREVIOUS_KUBE_VERSION = "v1.2.3"
UPGRADED_KUBE_VERSION = "v1.2.3-a"


class FakeKubeVersion(object):
    def __init__(
        self, obj_id=1, version=UPGRADED_KUBE_VERSION, target=True, state="active"
    ):
        self.id = obj_id
        self.uuid = str(uuid4())
        self.version = version
        self.target = target
        self.state = state
        self.upgrade_from = []
        self.applied_patches = []
        self.available_patches = []


class TestKubernetesAudit(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_regionone_sysinvclient = self._mock_object(
            kubernetes_audit, "SysinvClient"
        )
        self.mock_log = self._mock_object(kubernetes_audit, "LOG")

        self.mock_subcloud_sysinvclient = mock.MagicMock()

        self.kubernetes_audit = kubernetes_audit.KubernetesAudit()
        self.audit_manager = subcloud_audit_manager.SubcloudAuditManager()
        self.audit_manager.kubernetes_audit = self.kubernetes_audit

        self.subcloud = create_fake_subcloud(self.ctx)

    def _get_kubernetes_audit_data(self):
        (_, kubernetes_audit_data, _, _) = self.audit_manager._get_audit_data(
            False, True, False, False
        )
        return kubernetes_audit_data

    def _test_kubernetes_audit(self, sync_status):
        response = self.kubernetes_audit.get_subcloud_sync_status(
            self.mock_subcloud_sysinvclient(),
            self._get_kubernetes_audit_data(),
            self.subcloud.name,
        )

        self.assertEqual(response, sync_status)

    def test_kubernetes_audit_region_one_client_creation_exception(self):
        self.mock_regionone_sysinvclient.side_effect = Exception("fake")

        response = self._get_kubernetes_audit_data()

        self.assertIsNone(response)
        self.mock_log.exception.assert_called_with(
            "Failed init Sysinv Client, skip kubernetes audit."
        )

    def test_kubernetes_audit_skip_on_get_kube_upgrades_exception(self):
        self.mock_subcloud_sysinvclient().get_kube_upgrades.side_effect = Exception(
            "fake"
        )

        self._test_kubernetes_audit(None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Failed to get kubernetes upgrades, skip kubernetes "
            "audit."
        )

    def test_kubernetes_audit_skip_on_get_kube_versions_exception(self):
        self.mock_subcloud_sysinvclient().get_kube_versions.side_effect = Exception(
            "fake"
        )

        self._test_kubernetes_audit(None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Failed to get kubernetes versions, skip kubernetes "
            "audit."
        )

    def test_kubernetes_audit_out_of_sync_with_older_version(self):
        # Set the region one data as the upgraded version
        self.mock_regionone_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        # Return different kube versions in the subcloud
        self.mock_subcloud_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
        ]

        self._test_kubernetes_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_kubernetes_audit_out_of_sync_with_newer_version(self):
        # Set the region one data as the previous version
        self.mock_regionone_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
        ]
        # Return different kube versions in the subcloud
        self.mock_subcloud_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        self._test_kubernetes_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_kubernetes_audit_in_sync(self):
        self.mock_regionone_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=PREVIOUS_KUBE_VERSION, state="inactive"),
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        self.mock_subcloud_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION)
        ]

        self._test_kubernetes_audit(dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kubernetes_audit_in_sync_with_existing_upgrade(self):
        self.mock_subcloud_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        self.mock_regionone_sysinvclient().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]

        # If a subcloud has an existing upgrade, it is out of sync even if the kube
        # versions match
        self.mock_subcloud_sysinvclient().get_kube_upgrades.return_value = [
            mock.MagicMock()
        ]

        self._test_kubernetes_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
