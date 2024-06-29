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

import mock
from oslo_config import cfg

from dccommon import consts as dccommon_consts
from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.tests import base

CONF = cfg.CONF


class Load(object):
    def __init__(self, software_version, state):
        self.software_version = software_version
        self.state = state


class Upgrade(object):
    def __init__(self, state):
        self.state = state


class System(object):
    def __init__(self, software_version):
        self.software_version = software_version


class FakePatchingClientInSync(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self):
        if self.region == "RegionOne":
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.3": {
                    "sw_version": "17.07",
                    "repostate": "Committed",
                    "patchstate": "Committed",
                },
                "DC.4": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                # This patch won't make us out of sync because it is for
                # a different release.
                "OTHER_REL_DC.1": {
                    "sw_version": "17.08",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
            }
        elif self.region in [
            base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["region_name"],
        ]:
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.3": {
                    "sw_version": "17.07",
                    "repostate": "Committed",
                    "patchstate": "Committed",
                },
                "DC.4": {
                    "sw_version": "17.07",
                    "repostate": "Committed",
                    "patchstate": "Committed",
                },
            }
        else:
            return {}


class FakePatchingClientOutOfSync(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self):
        if self.region == "RegionOne":
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Partial-Apply",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
            }
        elif self.region == base.SUBCLOUD_1["region_name"]:
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Available",
                    "patchstate": "Available",
                },
            }
        elif self.region == base.SUBCLOUD_2["region_name"]:
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                }
            }
        elif self.region == base.SUBCLOUD_3["region_name"]:
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
            }
        elif self.region == base.SUBCLOUD_4["region_name"]:
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Partial-Apply",
                },
            }
        else:
            return {}


class FakePatchingClientExtraPatches(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint

    def query(self):
        if self.region == "RegionOne":
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
            }
        elif self.region == "subcloud1":
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.3": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
            }
        elif self.region == "subcloud2":
            return {
                "DC.1": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "DC.2": {
                    "sw_version": "17.07",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
                "OTHER_REL_DC.1": {
                    "sw_version": "17.08",
                    "repostate": "Applied",
                    "patchstate": "Applied",
                },
            }
        else:
            return {}


class FakeSysinvClientOneLoad(object):
    def __init__(self, region=None, session=None, endpoint=None):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load("17.07", "active")]
        self.upgrades = []
        self.system = System("17.07")

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        return self.upgrades

    def get_system(self):
        return self.system


class FakeSysinvClientOneLoadUnmatchedSoftwareVersion(object):
    def __init__(self, region=None, session=None, endpoint=None):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load("17.07", "active")]
        self.upgrades = []
        self.system = System("17.07")

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        return self.upgrades

    def get_system(self):
        if self.region == base.SUBCLOUD_2["region_name"]:
            return System("17.06")
        else:
            return self.system


class FakeSysinvClientOneLoadUpgradeInProgress(object):
    def __init__(self, region=None, session=None, endpoint=None):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.loads = [Load("17.07", "active")]
        self.upgrades = []
        self.system = System("17.07")

    def get_loads(self):
        return self.loads

    def get_upgrades(self):
        if self.region == base.SUBCLOUD_2["region_name"]:
            return [Upgrade("started")]
        else:
            return self.upgrades

    def get_system(self):
        return self.system


class TestPatchAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_rpc_api_manager_audit_worker_client()
        self._mock_openstack_driver(subcloud_audit_worker_manager)
        self._mock_sysinv_client(subcloud_audit_worker_manager)
        self._mock_subcloud_audit_manager_context()

        self.mock_subcloud_audit_manager_context.get_admin_context.return_value = (
            self.ctx
        )

        self.pm = patch_audit.PatchAudit(self.ctx)
        self.am = subcloud_audit_manager.SubcloudAuditManager()
        self.am.patch_audit = self.pm

    def get_patch_audit_data(self):
        (patch_audit_data, _, _, _, _) = self.am._get_audit_data(
            True, True, True, True, True
        )
        # Convert to dict like what would happen calling via RPC
        patch_audit_data = patch_audit_data.to_dict()
        return patch_audit_data

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    def test_periodic_patch_audit_in_sync(
        self, mock_openstack_driver, mock_patching_client, mock_sysinv_client
    ):
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        self.mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        patch_audit_data = self.get_patch_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }

        for index, subcloud in enumerate(subclouds.keys(), start=2):
            subcloud_region = subclouds[subcloud]

            patch_response = self.pm.subcloud_patch_audit(
                mock.MagicMock(),
                self.mock_sysinv_client(subcloud_region),
                f"192.168.1.{index}",
                subcloud,
                subcloud_region,
                patch_audit_data,
            )
            load_response = self.pm.subcloud_load_audit(
                self.mock_sysinv_client(subcloud_region), subcloud, patch_audit_data
            )

            self.assertEqual(patch_response, dccommon_consts.SYNC_STATUS_IN_SYNC)
            self.assertEqual(load_response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    def test_periodic_patch_audit_out_of_sync(
        self, mock_openstack_driver, mock_patching_client, mock_sysinv_client
    ):
        mock_patching_client.side_effect = FakePatchingClientOutOfSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        self.mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        patch_audit_data = self.get_patch_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
            base.SUBCLOUD_3["name"]: base.SUBCLOUD_3["region_name"],
            base.SUBCLOUD_4["name"]: base.SUBCLOUD_4["region_name"],
        }
        for index, subcloud in enumerate(subclouds.keys(), start=2):
            subcloud_region = subclouds[subcloud]

            patch_response = self.pm.subcloud_patch_audit(
                mock.MagicMock(),
                self.mock_sysinv_client(subcloud_region),
                f"192.168.1.{index}",
                subcloud,
                subcloud_region,
                patch_audit_data,
            )
            load_response = self.pm.subcloud_load_audit(
                self.mock_sysinv_client(subcloud_region), subcloud, patch_audit_data
            )

            expected_patch_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
            if subcloud == base.SUBCLOUD_3["name"]:
                expected_patch_response = dccommon_consts.SYNC_STATUS_IN_SYNC
            self.assertEqual(patch_response, expected_patch_response)
            self.assertEqual(load_response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    def test_periodic_patch_audit_extra_patches(
        self, mock_openstack_driver, mock_patching_client, mock_sysinv_client
    ):
        mock_patching_client.side_effect = FakePatchingClientExtraPatches
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoad
        self.mock_sysinv_client.side_effect = FakeSysinvClientOneLoad

        patch_audit_data = self.get_patch_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for index, subcloud in enumerate(subclouds.keys(), start=2):
            subcloud_region = subclouds[subcloud]

            patch_response = self.pm.subcloud_patch_audit(
                mock.MagicMock(),
                self.mock_sysinv_client(subcloud_region),
                f"192.168.1.{index}",
                subcloud,
                subcloud_region,
                patch_audit_data,
            )
            load_response = self.pm.subcloud_load_audit(
                self.mock_sysinv_client(subcloud_region), subcloud, patch_audit_data
            )

            self.assertEqual(patch_response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
            self.assertEqual(load_response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    def test_periodic_patch_audit_unmatched_software_version(
        self, mock_openstack_driver, mock_patching_client, mock_sysinv_client
    ):
        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUnmatchedSoftwareVersion
        self.mock_sysinv_client.side_effect = (
            FakeSysinvClientOneLoadUnmatchedSoftwareVersion
        )

        patch_audit_data = self.get_patch_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for index, subcloud in enumerate(subclouds.keys(), start=2):
            subcloud_region = subclouds[subcloud]

            patch_response = self.pm.subcloud_patch_audit(
                mock.MagicMock(),
                self.mock_sysinv_client(subcloud_region),
                f"192.168.1.{index}",
                subcloud,
                subcloud_region,
                patch_audit_data,
            )
            load_response = self.pm.subcloud_load_audit(
                self.mock_sysinv_client(subcloud_region), subcloud, patch_audit_data
            )

            expected_load_response = dccommon_consts.SYNC_STATUS_IN_SYNC

            if subcloud == base.SUBCLOUD_2["name"]:
                expected_load_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

            self.assertEqual(patch_response, dccommon_consts.SYNC_STATUS_IN_SYNC)
            self.assertEqual(load_response, expected_load_response)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    def test_periodic_patch_audit_upgrade_in_progress(
        self, mock_openstack_driver, mock_patching_client, mock_sysinv_client
    ):

        mock_patching_client.side_effect = FakePatchingClientInSync
        mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUpgradeInProgress
        self.mock_sysinv_client.side_effect = FakeSysinvClientOneLoadUpgradeInProgress

        patch_audit_data = self.get_patch_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for index, subcloud in enumerate(subclouds.keys(), start=2):
            subcloud_region = subclouds[subcloud]

            patch_response = self.pm.subcloud_patch_audit(
                mock.MagicMock(),
                self.mock_sysinv_client(subcloud_region),
                f"192.168.1.{index}",
                subcloud,
                subcloud_region,
                patch_audit_data,
            )
            load_response = self.pm.subcloud_load_audit(
                self.mock_sysinv_client(subcloud_region), subcloud, patch_audit_data
            )

            expected_load_response = dccommon_consts.SYNC_STATUS_IN_SYNC

            if subcloud == base.SUBCLOUD_2["name"]:
                expected_load_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

            self.assertEqual(patch_response, dccommon_consts.SYNC_STATUS_IN_SYNC)
            self.assertEqual(load_response, expected_load_response)
