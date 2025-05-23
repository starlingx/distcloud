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

import base64
import copy
import mock

from oslo_config import cfg
from oslo_utils import uuidutils

from dccommon import consts as dccommon_consts
from dccommon import ostree_mount
from dcmanager.audit import rpcapi
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.common import utils as cutils
from dcmanager.db import api as db_api
from dcmanager.orchestrator import orchestrator_manager
from dcmanager.orchestrator import rpcapi as orchestrator_rpc_api

from dcmanager.tests import base


OAM_FLOATING_IP = "10.10.10.12"
CONF = cfg.CONF
FAKE_ID = "1"
FAKE_SW_UPDATE_DATA = {
    "type": consts.SW_UPDATE_TYPE_SOFTWARE,
    "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    "max-parallel-subclouds": "2",
    "stop-on-failure": "true",
    "release_id": "stx-10.0.0",
    "state": consts.SW_UPDATE_STATE_INITIAL,
}

FAKE_SW_PRESTAGE_DATA = {
    "type": consts.SW_UPDATE_TYPE_PRESTAGE,
    "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    "max-parallel-subclouds": "2",
    "stop-on-failure": "true",
    "force": "false",
    "state": consts.SW_UPDATE_STATE_INITIAL,
}

health_report_no_mgmt_alarm = "System Health:\n \
    All hosts are provisioned: [Fail]\n \
    1 Unprovisioned hosts\n \
    All hosts are unlocked/enabled: [OK]\n \
    All hosts have current configurations: [OK]\n \
    All hosts are patch current: [OK]\n \
    No alarms: [OK]\n \
    All kubernetes nodes are ready: [OK]\n \
    All kubernetes control plane pods are ready: [OK]"


class Subcloud(object):
    def __init__(self, id, name, group_id, is_managed, is_online):
        self.id = id
        self.name = name
        self.software_version = "12.04"
        self.group_id = group_id
        if is_managed:
            self.management_state = dccommon_consts.MANAGEMENT_MANAGED
        else:
            self.management_state = dccommon_consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = dccommon_consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = dccommon_consts.AVAILABILITY_OFFLINE


# All orch_threads can be mocked the same way
class FakeOrchThread(object):
    def __init__(self):
        # Mock methods that are called in normal execution of this thread
        self.start = mock.MagicMock()


class FakeDCManagerAuditAPI(object):
    def __init__(self):
        self.trigger_firmware_audit = mock.MagicMock()
        self.trigger_kube_rootca_update_audit = mock.MagicMock()


class TestOrchestratorManager(base.DCManagerTestCase):
    @staticmethod
    def create_subcloud(ctx, name, group_id, is_managed, is_online, sw_version="stx-9"):
        values = {
            "name": name,
            "description": "subcloud1 description",
            "location": "subcloud1 location",
            "software_version": sw_version,
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.3",
            "management_end_ip": "192.168.101.4",
            "systemcontroller_gateway_ip": "192.168.204.101",
            "external_oam_subnet_ip_family": "4",
            "deploy_status": "not-deployed",
            "error_description": "No errors present",
            "region_name": uuidutils.generate_uuid().replace("-", ""),
            "openstack_installed": False,
            "group_id": group_id,
            "data_install": "data from install",
        }
        subcloud = db_api.subcloud_create(ctx, **values)
        if is_managed:
            state = dccommon_consts.MANAGEMENT_MANAGED
            subcloud = db_api.subcloud_update(ctx, subcloud.id, management_state=state)
        if is_online:
            status = dccommon_consts.AVAILABILITY_ONLINE
            subcloud = db_api.subcloud_update(
                ctx, subcloud.id, availability_status=status
            )
        return subcloud

    @staticmethod
    def create_subcloud_group(ctx, name, update_apply_type, max_parallel_subclouds):
        values = {
            "name": name,
            "description": "subcloud1 description",
            "update_apply_type": update_apply_type,
            "max_parallel_subclouds": max_parallel_subclouds,
        }
        return db_api.subcloud_group_create(ctx, **values)

    @staticmethod
    def update_subcloud_status(ctx, subcloud_id, endpoint=None, status=None):
        if endpoint:
            endpoint_type = endpoint
        else:
            endpoint_type = dccommon_consts.AUDIT_TYPE_SOFTWARE
        if status:
            sync_status = status
        else:
            sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        subcloud_status = db_api.subcloud_status_update(
            ctx, subcloud_id, endpoint_type, sync_status
        )
        return subcloud_status

    @staticmethod
    def create_strategy(ctx, strategy_type, state):
        values = {
            "type": strategy_type,
            "subcloud_apply_type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max_parallel_subclouds": 2,
            "stop_on_failure": True,
            "state": state,
        }
        return db_api.sw_update_strategy_create(ctx, **values)

    @staticmethod
    def create_strategy_step(ctx, state):
        values = {
            "subcloud_id": 1,
            "stage": 1,
            "state": state,
            "details": "Dummy details",
        }
        return db_api.strategy_step_create(ctx, **values)

    def setUp(self):
        super().setUp()
        # Mock the context
        mock_get_admin_context = self._mock_object(context, "get_admin_context")
        mock_get_admin_context.return_value = self.ctx

        # Mock the dcmanager audit API
        mock_dcmanager_audit_api = self._mock_object(rpcapi, "ManagerAuditClient")
        mock_dcmanager_audit_api.return_value = FakeDCManagerAuditAPI()

        self._mock_object(orchestrator_rpc_api, "ManagerOrchestratorWorkerClient")

        # Mock for logs
        self._mock_object(orchestrator_manager, "LOG")

        # Mock ostree_mount validate_ostree_iso_mount
        self._mock_object(ostree_mount, "validate_ostree_iso_mount")

        # Fake subcloud groups
        # Group 1 exists by default in database with max_parallel 2 and
        # apply_type parallel
        self.fake_group2 = self.create_subcloud_group(
            self.ctx, "Group2", consts.SUBCLOUD_APPLY_TYPE_SERIAL, 2
        )
        self.fake_group3 = self.create_subcloud_group(
            self.ctx, "Group3", consts.SUBCLOUD_APPLY_TYPE_PARALLEL, 2
        )
        self.fake_group4 = self.create_subcloud_group(
            self.ctx, "Group4", consts.SUBCLOUD_APPLY_TYPE_SERIAL, 2
        )
        self.fake_group5 = self.create_subcloud_group(
            self.ctx, "Group5", consts.SUBCLOUD_APPLY_TYPE_PARALLEL, 2
        )

    def test_init(self):
        um = orchestrator_manager.OrchestratorManager()
        self.assertIsNotNone(um)
        self.assertEqual("orchestrator_manager", um.service_name)
        self.assertEqual("localhost", um.host)

    def test_create_sw_update_strategy_no_subclouds(self):
        um = orchestrator_manager.OrchestratorManager()
        # No strategy will be created, so it should raise:
        # 'Bad strategy request: Strategy has no steps to apply'
        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=FAKE_SW_UPDATE_DATA,
        )

    def test_create_sw_update_strategy_for_a_single_group(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group2.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx,
            "subcloud2",
            self.fake_group2.id,
            is_managed=False,
            is_online=True,
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["subcloud_group"] = str(self.fake_group2.id)
        um = orchestrator_manager.OrchestratorManager()
        response = um.create_sw_update_strategy(self.ctx, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response["max-parallel-subclouds"], 1)
        self.assertEqual(
            response["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_SERIAL
        )
        self.assertEqual(response["type"], FAKE_SW_UPDATE_DATA["type"])

        # Verify strategy step was created as expected
        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(strategy_steps[0]["state"], consts.STRATEGY_STATE_INITIAL)
        self.assertEqual(strategy_steps[0]["details"], "")
        self.assertEqual(strategy_steps[0]["subcloud_id"], 1)

    def test_create_sw_update_strategy_parallel_for_a_single_group(self):
        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        )

        fake_subcloud2 = self.create_subcloud(
            self.ctx,
            "subcloud2",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud2.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        )

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_SOFTWARE
        data["subcloud_group"] = str(self.fake_group3.id)
        um = orchestrator_manager.OrchestratorManager()
        response = um.create_sw_update_strategy(self.ctx, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response["max-parallel-subclouds"], 2)
        self.assertEqual(
            response["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(response["type"], consts.SW_UPDATE_TYPE_SOFTWARE)

        # Verify the strategy step list
        subcloud_ids = [1, 2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    @mock.patch.object(prestage, "initial_subcloud_validate")
    @mock.patch.object(prestage, "global_prestage_validate")
    def test_create_sw_prestage_strategy_parallel_for_a_single_group(
        self,
        mock_global_prestage_validate,
        mock_initial_subcloud_validate,
    ):
        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        )

        fake_subcloud2 = self.create_subcloud(
            self.ctx,
            "subcloud2",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud2.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        )

        mock_global_prestage_validate.return_value = None
        mock_initial_subcloud_validate.return_value = None

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode("testpass".encode("utf-8"))).decode("ascii")
        data["sysadmin_password"] = fake_password

        data["subcloud_group"] = str(self.fake_group3.id)
        um = orchestrator_manager.OrchestratorManager()
        response = um.create_sw_update_strategy(self.ctx, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response["max-parallel-subclouds"], 2)
        self.assertEqual(
            response["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(response["type"], consts.SW_UPDATE_TYPE_PRESTAGE)

        # Verify the strategy step list
        subcloud_ids = [1, 2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    @mock.patch.object(prestage, "initial_subcloud_validate")
    @mock.patch.object(prestage, "global_prestage_validate")
    def test_create_sw_prestage_strategy_load_insync_out_of_sync_unknown_and_no_load(
        self,
        mock_global_prestage_validate,
        mock_initial_subcloud_validate,
    ):
        # Create fake subclouds and respective status
        # Subcloud1 will be prestaged load in sync
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_IN_SYNC,
        )

        # Subcloud2 will be prestaged load is None
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud2.id, dccommon_consts.AUDIT_TYPE_SOFTWARE, None
        )

        # Subcloud3 will be prestaged load out of sync
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud3.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        )

        # Subcloud4 will be prestaged sync unknown
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud4.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        )

        mock_global_prestage_validate.return_value = None
        mock_initial_subcloud_validate.return_value = None

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode("testpass".encode("utf-8"))).decode("ascii")
        data["sysadmin_password"] = fake_password

        um = orchestrator_manager.OrchestratorManager()
        response = um.create_sw_update_strategy(self.ctx, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response["max-parallel-subclouds"], 2)
        self.assertEqual(
            response["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(response["type"], consts.SW_UPDATE_TYPE_PRESTAGE)

        # Verify the strategy step list
        subcloud_ids = [1, 2, 3, 4]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    @mock.patch.object(prestage, "initial_subcloud_validate")
    @mock.patch.object(cutils, "get_system_controller_deploy", return_value=None)
    def test_create_sw_prestage_strategy_no_password(
        self,
        mock_controller_upgrade,
        mock_initial_subcloud_validate,
    ):
        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        )

        fake_subcloud2 = self.create_subcloud(
            self.ctx,
            "subcloud2",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud2.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        )

        mock_initial_subcloud_validate.return_value = None
        mock_controller_upgrade.return_value = list()

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        data["sysadmin_password"] = ""
        data["subcloud_group"] = str(self.fake_group3.id)
        um = orchestrator_manager.OrchestratorManager()

        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=data,
        )

    @mock.patch.object(cutils, "get_system_controller_deploy", return_value=None)
    def test_create_sw_prestage_strategy_backup_in_progress(
        self,
        mock_controller_upgrade,
    ):
        mock_controller_upgrade.return_value = list()

        # Create fake subcloud and respective status (managed & online)
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)
        db_api.subcloud_update(
            self.ctx,
            fake_subcloud1.id,
            backup_status=consts.BACKUP_STATE_IN_PROGRESS,
        )

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode("testpass".encode("utf-8"))).decode("ascii")
        data["sysadmin_password"] = fake_password
        data["cloud_name"] = "subcloud1"

        um = orchestrator_manager.OrchestratorManager()

        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=data,
        )

    def test_create_sw_update_strategy_cloud_name_not_exists(self):
        # Create fake subclouds and respective status
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)

        # Create a strategy with a cloud_name that doesn't exist
        data["cloud_name"] = "subcloud2"
        um = orchestrator_manager.OrchestratorManager()
        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=data,
        )

    def test_create_sw_update_strategy_parallel(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=False, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud4.id, None, dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(
            self.ctx, "subcloud5", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(
            self.ctx, "subcloud6", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(
            self.ctx, "subcloud7", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud7.id)

        um = orchestrator_manager.OrchestratorManager()
        strategy_dict = um.create_sw_update_strategy(
            self.ctx, payload=FAKE_SW_UPDATE_DATA
        )

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict["max-parallel-subclouds"], 2)
        self.assertEqual(
            strategy_dict["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_subcloud_in_sync_out_of_sync(self):
        # Subcloud 1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )

        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        )

        # Subcloud 2 will not be patched because it is offline
        fake_subcloud2 = self.create_subcloud(
            self.ctx,
            "subcloud2",
            self.fake_group3.id,
            is_managed=True,
            is_online=False,
        )

        self.update_subcloud_status(
            self.ctx,
            fake_subcloud2.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        )

        # Subcloud 3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx,
            "subcloud3",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )

        self.update_subcloud_status(
            self.ctx,
            fake_subcloud3.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        )

        # Subcloud 4 will not be patched because it is in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx,
            "subcloud4",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )

        self.update_subcloud_status(
            self.ctx,
            fake_subcloud4.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_IN_SYNC,
        )

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["subcloud_group"] = str(self.fake_group3.id)
        um = orchestrator_manager.OrchestratorManager()
        response = um.create_sw_update_strategy(self.ctx, payload=data)

        # Verify strategy was created as expected using group values
        self.assertEqual(response["max-parallel-subclouds"], 2)
        self.assertEqual(
            response["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(response["type"], consts.SW_UPDATE_TYPE_SOFTWARE)

        # Verify the strategy step list
        subcloud_ids = [1, 3]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        subcloud_id_processed = []
        for strategy_step in strategy_step_list:
            subcloud_id_processed.append(strategy_step.subcloud_id)
        self.assertEqual(subcloud_ids, subcloud_id_processed)

    @mock.patch.object(prestage, "initial_subcloud_validate")
    @mock.patch.object(cutils, "get_system_controller_deploy", return_value=None)
    def test_create_sw_prestage_strategy_parallel(
        self,
        mock_controller_upgrade,
        mock_initial_subcloud_validate,
    ):
        # Create fake subclouds and respective status
        # Subcloud1 will be prestaged
        self.create_subcloud(self.ctx, "subcloud1", 1, is_managed=True, is_online=True)

        # Subcloud2 will not be prestaged because not managed
        self.create_subcloud(self.ctx, "subcloud2", 1, is_managed=False, is_online=True)

        # Subcloud3 will be prestaged
        self.create_subcloud(self.ctx, "subcloud3", 1, is_managed=True, is_online=True)

        # Subcloud4 will not be prestaged because offline
        self.create_subcloud(self.ctx, "subcloud4", 2, is_managed=True, is_online=False)

        # Subcloud5 will be prestaged
        self.create_subcloud(self.ctx, "subcloud5", 2, is_managed=True, is_online=True)

        # Subcloud6 will be prestaged
        self.create_subcloud(self.ctx, "subcloud6", 3, is_managed=True, is_online=True)

        # Subcloud7 will be prestaged
        self.create_subcloud(self.ctx, "subcloud7", 3, is_managed=True, is_online=True)

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode("testpass".encode("utf-8"))).decode("ascii")
        data["sysadmin_password"] = fake_password
        fake_release = "24.09"
        data[consts.PRESTAGE_REQUEST_RELEASE] = fake_release

        um = orchestrator_manager.OrchestratorManager()
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        mock_initial_subcloud_validate.return_value = None
        mock_controller_upgrade.return_value = list()

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict["max-parallel-subclouds"], 2)
        self.assertEqual(
            strategy_dict["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(
            fake_release,
            strategy_dict["extra-args"].get(consts.PRESTAGE_SOFTWARE_VERSION),
        )

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        subcloud_id_processed = []
        for index, strategy_step in enumerate(strategy_step_list):
            subcloud_id_processed.append(strategy_step.subcloud_id)
        self.assertEqual(subcloud_ids, subcloud_id_processed)

    def test_create_sw_update_strategy_serial(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=False, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud4.id, None, dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(
            self.ctx, "subcloud5", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(
            self.ctx, "subcloud6", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(
            self.ctx, "subcloud7", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud7.id)

        um = orchestrator_manager.OrchestratorManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["subcloud-apply-type"] = consts.SUBCLOUD_APPLY_TYPE_SERIAL
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict["max-parallel-subclouds"], 1)
        self.assertEqual(
            strategy_dict["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_SERIAL
        )

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_strategy_using_group_apply_type(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=False, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud4.id, None, dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(
            self.ctx, "subcloud5", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(
            self.ctx, "subcloud6", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(
            self.ctx, "subcloud7", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud7.id)

        # Subcloud8 will be patched
        fake_subcloud8 = self.create_subcloud(
            self.ctx, "subcloud8", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud8.id)

        # Subcloud9 will be patched
        fake_subcloud9 = self.create_subcloud(
            self.ctx, "subcloud9", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud9.id)

        # Subcloud10 will be patched
        fake_subcloud10 = self.create_subcloud(
            self.ctx, "subcloud10", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud10.id)

        # Subcloud11 will be patched
        fake_subcloud11 = self.create_subcloud(
            self.ctx, "subcloud11", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud11.id)

        # Subcloud12 will be patched
        fake_subcloud12 = self.create_subcloud(
            self.ctx, "subcloud12", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud12.id)

        # Subcloud13 will be patched
        fake_subcloud13 = self.create_subcloud(
            self.ctx, "subcloud13", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud13.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        del data["subcloud-apply-type"]

        um = orchestrator_manager.OrchestratorManager()
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        # Assert that group values are being used for subcloud_apply_type
        self.assertEqual(strategy_dict["subcloud-apply-type"], None)

        # Assert that values passed through CLI are used instead of
        # group values for max_parallel_subclouds
        self.assertEqual(strategy_dict["max-parallel-subclouds"], 2)

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_strategy_using_group_max_parallel(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=False, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud4.id, None, dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(
            self.ctx, "subcloud5", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(
            self.ctx, "subcloud6", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(
            self.ctx, "subcloud7", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud7.id)

        # Subcloud8 will be patched
        fake_subcloud8 = self.create_subcloud(
            self.ctx, "subcloud8", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud8.id)

        # Subcloud9 will be patched
        fake_subcloud9 = self.create_subcloud(
            self.ctx, "subcloud9", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud9.id)

        # Subcloud10 will be patched
        fake_subcloud10 = self.create_subcloud(
            self.ctx, "subcloud10", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud10.id)

        # Subcloud11 will be patched
        fake_subcloud11 = self.create_subcloud(
            self.ctx, "subcloud11", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud11.id)

        # Subcloud12 will be patched
        fake_subcloud12 = self.create_subcloud(
            self.ctx, "subcloud12", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud12.id)

        # Subcloud13 will be patched
        fake_subcloud13 = self.create_subcloud(
            self.ctx, "subcloud13", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud13.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        del data["max-parallel-subclouds"]

        um = orchestrator_manager.OrchestratorManager()
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        # Assert that values passed through CLI are used instead of
        # group values for max_parallel_subclouds
        self.assertEqual(
            strategy_dict["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )

        # Assert that group values are being used for subcloud_apply_type
        self.assertEqual(
            strategy_dict["max-parallel-subclouds"],
            consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS,
        )

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_strategy_using_all_group_values(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=False, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud4.id, None, dccommon_consts.SYNC_STATUS_IN_SYNC
        )
        # Subcloud5 will be patched
        fake_subcloud5 = self.create_subcloud(
            self.ctx, "subcloud5", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud5.id)

        # Subcloud6 will be patched
        fake_subcloud6 = self.create_subcloud(
            self.ctx, "subcloud6", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud6.id)

        # Subcloud7 will be patched
        fake_subcloud7 = self.create_subcloud(
            self.ctx, "subcloud7", 3, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud7.id)

        # Subcloud8 will be patched
        fake_subcloud8 = self.create_subcloud(
            self.ctx, "subcloud8", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud8.id)

        # Subcloud9 will be patched
        fake_subcloud9 = self.create_subcloud(
            self.ctx, "subcloud9", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud9.id)

        # Subcloud10 will be patched
        fake_subcloud10 = self.create_subcloud(
            self.ctx, "subcloud10", 4, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud10.id)

        # Subcloud11 will be patched
        fake_subcloud11 = self.create_subcloud(
            self.ctx, "subcloud11", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud11.id)

        # Subcloud12 will be patched
        fake_subcloud12 = self.create_subcloud(
            self.ctx, "subcloud12", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud12.id)

        # Subcloud13 will be patched
        fake_subcloud13 = self.create_subcloud(
            self.ctx, "subcloud13", 5, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud13.id)

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        del data["subcloud-apply-type"]
        del data["max-parallel-subclouds"]

        um = orchestrator_manager.OrchestratorManager()
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        # Assert that group values are being used
        self.assertEqual(
            strategy_dict["max-parallel-subclouds"],
            consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS,
        )
        self.assertEqual(strategy_dict["subcloud-apply-type"], None)

        # Verify the strategy step list
        subcloud_ids = [1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_strategy_unknown_sync_status(self):
        # Create fake subclouds and respective status
        # Subcloud1 will be patched
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will not be patched because not managed
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=False, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be patched
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will not be patched because patching is not in sync
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 2, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx, fake_subcloud4.id, None, dccommon_consts.SYNC_STATUS_UNKNOWN
        )

        um = orchestrator_manager.OrchestratorManager()
        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=FAKE_SW_UPDATE_DATA,
        )

    @mock.patch.object(prestage, "_get_prestage_subcloud_info")
    @mock.patch.object(cutils, "get_system_controller_deploy", return_value=None)
    def test_create_sw_prestage_strategy_duplex(
        self,
        mock_controller_upgrade,
        mock_prestage_subcloud_info,
    ):
        # Create fake subclouds and respective status

        # A note on subcloud system mode = duplex checking: For this test case
        # it will be *included* in the strategy_step_list.  It is not until the
        # strategy is applied that the subcloud is skipped.  During
        # orchestration, we will see a raised PrestagePreCheckFailedException
        # from prestage.validate_prestage() during the PrestagePreCheckState
        # from the orchestration. That state is the first state executed by
        # the orchestrator.
        #
        # Therefore, subcloud1 will be included in the strategy but not be
        # prestaged because during the apply we find out it is a duplex
        self.create_subcloud(self.ctx, "subcloud1", 1, is_managed=True, is_online=True)

        data = copy.copy(FAKE_SW_PRESTAGE_DATA)
        fake_password = (base64.b64encode("testpass".encode("utf-8"))).decode("ascii")
        data["sysadmin_password"] = fake_password

        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = (
            consts.SYSTEM_MODE_DUPLEX,
            health_report_no_mgmt_alarm,
            OAM_FLOATING_IP,
        )

        um = orchestrator_manager.OrchestratorManager()
        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=data,
        )

    def test_create_sw_update_strategy_offline_subcloud(self):
        # Create fake subclouds and respective status
        # Subcloud1 will not be included in the strategy as it's offline
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=False
        )
        self.update_subcloud_status(self.ctx, fake_subcloud1.id)

        # Subcloud2 will be included in the strategy as it's online
        fake_subcloud2 = self.create_subcloud(
            self.ctx, "subcloud2", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud2.id)

        # Subcloud3 will be included in the strategy as it's online
        fake_subcloud3 = self.create_subcloud(
            self.ctx, "subcloud3", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud3.id)

        # Subcloud4 will be included in the strategy as it's online
        fake_subcloud4 = self.create_subcloud(
            self.ctx, "subcloud4", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(self.ctx, fake_subcloud4.id)

        um = orchestrator_manager.OrchestratorManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["max-parallel-subclouds"] = 10
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(strategy_dict["max-parallel-subclouds"], 10)
        self.assertEqual(
            strategy_dict["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(strategy_dict["type"], consts.SW_UPDATE_TYPE_SOFTWARE)

        # Verify the strategy step list
        subcloud_ids = [2, 3, 4]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_strategy(self):
        # Subcloud 1 will not be upgraded
        fake_subcloud1 = self.create_subcloud(
            self.ctx,
            "subcloud1",
            self.fake_group3.id,
            is_managed=True,
            is_online=False,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        )

        # Subcloud 2 will be upgraded
        fake_subcloud2 = self.create_subcloud(
            self.ctx,
            "subcloud2",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud2.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        )

        # Subcloud 3 will not be upgraded because it is already load in-sync
        fake_subcloud3 = self.create_subcloud(
            self.ctx,
            "subcloud3",
            self.fake_group3.id,
            is_managed=True,
            is_online=True,
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud3.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_IN_SYNC,
        )

        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_SOFTWARE
        data["subcloud_group"] = str(self.fake_group3.id)

        um = orchestrator_manager.OrchestratorManager()
        strategy_dict = um.create_sw_update_strategy(self.ctx, payload=data)

        # Assert that values passed through CLI are used instead of group values
        self.assertEqual(
            strategy_dict["subcloud-apply-type"], consts.SUBCLOUD_APPLY_TYPE_PARALLEL
        )
        self.assertEqual(strategy_dict["type"], consts.SW_UPDATE_TYPE_SOFTWARE)

        subcloud_ids = [2]
        strategy_step_list = db_api.strategy_step_get_all(self.ctx)
        for index, strategy_step in enumerate(strategy_step_list):
            self.assertEqual(subcloud_ids[index], strategy_step.subcloud_id)

    def test_create_sw_update_strategy_in_sync_offline_subcloud(self):
        # This test verifies that a bad request exception is raised because the software
        # sync status of the offline subcloud is in-sync.
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=False
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_IN_SYNC,
        )

        um = orchestrator_manager.OrchestratorManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_SOFTWARE
        data["cloud_name"] = "subcloud1"

        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=data,
        )

    def test_create_sw_update_strategy_online_subcloud(self):
        # A bad request exception will be raised if the subcloud software sync status
        # is unknown.
        fake_subcloud1 = self.create_subcloud(
            self.ctx, "subcloud1", 1, is_managed=True, is_online=True
        )
        self.update_subcloud_status(
            self.ctx,
            fake_subcloud1.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        )

        um = orchestrator_manager.OrchestratorManager()
        data = copy.copy(FAKE_SW_UPDATE_DATA)
        data["type"] = consts.SW_UPDATE_TYPE_SOFTWARE
        data["cloud_name"] = "subcloud1"

        self.assertRaises(
            exceptions.BadRequest,
            um.create_sw_update_strategy,
            self.ctx,
            payload=data,
        )

    def test_delete_sw_update_strategy(self):
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )
        um = orchestrator_manager.OrchestratorManager()
        deleted_strategy = um.delete_sw_update_strategy(self.ctx)
        self.assertEqual(deleted_strategy["state"], consts.SW_UPDATE_STATE_DELETING)

    def test_delete_sw_update_strategy_scoped(self):
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )
        um = orchestrator_manager.OrchestratorManager()
        deleted_strategy = um.delete_sw_update_strategy(
            self.ctx, update_type=consts.SW_UPDATE_TYPE_SOFTWARE
        )
        self.assertEqual(deleted_strategy["state"], consts.SW_UPDATE_STATE_DELETING)

    def test_delete_sw_update_strategy_bad_scope(self):
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_PRESTAGE, consts.SW_UPDATE_STATE_INITIAL
        )
        um = orchestrator_manager.OrchestratorManager()
        # the strategy is PRESTAGE. The delete for SW-DEPLOY should fail
        self.assertRaises(
            exceptions.NotFound,
            um.delete_sw_update_strategy,
            self.ctx,
            update_type=consts.SW_UPDATE_TYPE_SOFTWARE,
        )

    def test_delete_sw_update_strategy_invalid_state(self):
        # Create fake strategy
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_APPLYING
        )
        um = orchestrator_manager.OrchestratorManager()
        self.assertRaises(exceptions.BadRequest, um.delete_sw_update_strategy, self.ctx)

    def test_apply_sw_update_strategy(self):
        # Create fake strategy
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )

        um = orchestrator_manager.OrchestratorManager()
        updated_strategy = um.apply_sw_update_strategy(self.ctx)
        self.assertEqual(updated_strategy["state"], consts.SW_UPDATE_STATE_APPLYING)

    def test_apply_sw_update_strategy_invalid_state(self):
        # Create fake strategy
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_APPLYING
        )
        um = orchestrator_manager.OrchestratorManager()
        self.assertRaises(exceptions.BadRequest, um.apply_sw_update_strategy, self.ctx)

    def test_abort_sw_update_strategy(self):
        # Create fake strategy
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_APPLYING
        )

        um = orchestrator_manager.OrchestratorManager()
        aborted_strategy = um.abort_sw_update_strategy(self.ctx)
        self.assertEqual(
            aborted_strategy["state"], consts.SW_UPDATE_STATE_ABORT_REQUESTED
        )

    def test_abort_sw_update_strategy_invalid_state(self):
        # Create fake strategy
        self.create_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_COMPLETE
        )

        um = orchestrator_manager.OrchestratorManager()
        self.assertRaises(exceptions.BadRequest, um.apply_sw_update_strategy, self.ctx)
