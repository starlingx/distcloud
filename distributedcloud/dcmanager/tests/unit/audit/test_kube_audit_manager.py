# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import uuid

from dccommon import consts as dccommon_consts
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.tests import base

PREVIOUS_KUBE_VERSION = "v1.2.3"
UPGRADED_KUBE_VERSION = "v1.2.3-a"


class FakeKubeVersion(object):
    def __init__(
        self, obj_id=1, version=UPGRADED_KUBE_VERSION, target=True, state="active"
    ):
        self.id = obj_id
        self.uuid = str(uuid.uuid4())
        self.version = version
        self.target = target
        self.state = state
        self.upgrade_from = []
        self.applied_patches = []
        self.available_patches = []


class FakeKubeUpgrade(object):
    def __init__(self):
        pass


class TestKubernetesAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_rpc_api_manager_audit_worker_client()

        # For the OpenStackDriver and SysinvClient that are duplicated, since some
        # of them are not used directly, the variables are overriden by the mock
        # method
        self._mock_openstack_driver(kubernetes_audit)
        self._mock_sysinv_client(kubernetes_audit)

        self._mock_sysinv_client(kubernetes_audit)
        self.kube_sysinv_client = self.mock_sysinv_client

        self._mock_sysinv_client(subcloud_audit_worker_manager)

        # Set the kube upgrade objects as being empty for all regions
        self.kube_sysinv_client().get_kube_upgrades.return_value = []

        self.audit = kubernetes_audit.KubernetesAudit()
        self.am = subcloud_audit_manager.SubcloudAuditManager()
        self.am.kubernetes_audit = self.audit

    def get_kube_audit_data(self):
        (_, _, kubernetes_audit_data, _, _) = self.am._get_audit_data(
            True, True, True, True, True
        )
        return kubernetes_audit_data

    def test_no_kubernetes_audit_data_to_sync(self):
        kubernetes_audit_data = self.get_kube_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.audit.subcloud_kubernetes_audit(
                self.mock_sysinv_client(), name, kubernetes_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kubernetes_audit_data_out_of_sync_older(self):

        # Set the region one data as being the upgraded version
        self.kube_sysinv_client().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            # return different kube versions in the subclouds
            self.kube_sysinv_client().get_kube_versions.return_value = [
                FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
            ]
            response = self.audit.subcloud_kubernetes_audit(
                self.mock_sysinv_client(), name, kubernetes_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_kubernetes_audit_data_out_of_sync_newer(self):

        # Set the region one data as being the previous version
        self.kube_sysinv_client().get_kube_versions.return_value = [
            FakeKubeVersion(version=PREVIOUS_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            # return different kube versions in the subclouds
            self.kube_sysinv_client().get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            response = self.audit.subcloud_kubernetes_audit(
                self.mock_sysinv_client(), name, kubernetes_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_kubernetes_audit_data_in_sync(self):

        # Set the region one data as being the upgraded version
        self.kube_sysinv_client().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        self.mock_sysinv_client().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION)
        ]
        kubernetes_audit_data = self.get_kube_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            # return same kube versions in the subclouds
            self.kube_sysinv_client().get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            response = self.audit.subcloud_kubernetes_audit(
                self.mock_sysinv_client(), name, kubernetes_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_kubernetes_audit_data_in_sync_but_existing_upgrade(self):
        # If a subcloud has an existing upgrade, it is out of sync
        # even if the kube versions match

        # mock that there is a kube upgrade (only queried in subclouds)
        self.kube_sysinv_client().get_kube_upgrades.return_value = [FakeKubeUpgrade()]
        # Set the region one data as being the upgraded version
        self.kube_sysinv_client().get_kube_versions.return_value = [
            FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
        ]
        kubernetes_audit_data = self.get_kube_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            # return same kube versions in the subclouds
            self.kube_sysinv_client().get_kube_versions.return_value = [
                FakeKubeVersion(version=UPGRADED_KUBE_VERSION),
            ]
            response = self.audit.subcloud_kubernetes_audit(
                self.mock_sysinv_client(), name, kubernetes_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
