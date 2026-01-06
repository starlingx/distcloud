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

import datetime
import mock

import eventlet
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon import ostree_mount
from dcmanager.audit import rpcapi
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator import orchestrator_manager
from dcmanager.orchestrator import rpcapi as orchestrator_rpc_api
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud


class BaseTestOrchestratorManager(DCManagerTestCase):
    """Base test class"""

    def setUp(self):
        super().setUp()

        # Mock the context
        mock_get_admin_context = self._mock_object(context, "get_admin_context")
        mock_get_admin_context.return_value = self.ctx
        self.mock_rpc_audit = self._mock_object(rpcapi, "ManagerAuditClient")
        self.mock_rpc_orchestrator_worker = self._mock_object(
            orchestrator_rpc_api, "ManagerOrchestratorWorkerClient"
        )
        self._mock_object(orchestrator_manager, "LOG")
        self._mock_object(ostree_mount, "validate_ostree_iso_mount")
        self.mock_scheduler = self._mock_object(orchestrator_manager, "scheduler")

        # Fake subcloud groups
        # Group 1 exists by default in database with max_parallel 2 and
        # apply_type parallel
        self.sc_group2 = fake_subcloud.create_fake_subcloud_group(
            self.ctx,
            name="Group2",
            update_apply_type=consts.SUBCLOUD_APPLY_TYPE_SERIAL,
            max_parallel_subclouds=6,
        )
        self.sc_group3 = fake_subcloud.create_fake_subcloud_group(
            self.ctx, name="Group3", max_parallel_subclouds=5
        )

        self.subcloud1 = fake_subcloud.create_fake_subcloud(
            self.ctx, name="subcloud1", group_id=self.sc_group3.id
        )
        self.subcloud2 = fake_subcloud.create_fake_subcloud(
            self.ctx, name="subcloud2", group_id=self.sc_group3.id
        )
        self.subcloud3 = fake_subcloud.create_fake_subcloud(
            self.ctx, name="subcloud3", group_id=self.sc_group3.id
        )

        self.orchestrator_manager = orchestrator_manager.OrchestratorManager()

        # The database mock needs to be done later to avoid the requests from the
        # class setup
        self.mock_db_api = self._mock_object(orchestrator_manager, "db_api", db_api)
        self.mock_utils_db_api = self._mock_object(utils, "db_api", db_api)
        self.mock_log = self._mock_object(orchestrator_manager, "LOG")


class TestOrchestratorManager(BaseTestOrchestratorManager):
    """Test class for the Orchestrator Manager"""

    def setUp(self):
        super().setUp()

    def test_init(self):
        self.assertIsNotNone(self.orchestrator_manager)
        self.assertEqual("orchestrator_manager", self.orchestrator_manager.service_name)
        self.assertEqual("localhost", self.orchestrator_manager.host)

    def test_init_without_strategy(self):
        """Test init without strategy"""

        self.orchestrator_manager = orchestrator_manager.OrchestratorManager()

        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_scheduler.start.assert_not_called()
        self.mock_log.info.assert_not_called()
        self.mock_log.debug.assert_called_with(
            "There isn't an active strategy to orchestrate, skipping monitoring",
        )

    def test_init_with_strategy_not_applying(self):
        """Test init with strategy not applying"""

        fake_strategy.create_fake_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )

        self.orchestrator_manager = orchestrator_manager.OrchestratorManager()

        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_scheduler.start.assert_not_called()
        # Debug is called once because of the initialization message
        self.mock_log.debug.assert_called_once()
        self.mock_log.info.assert_not_called()

    def test_init_with_strategy_deleting_or_applying(self):
        """Test init with strategy deleting or applying"""

        strategy = fake_strategy.create_fake_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )

        for state in [consts.SW_UPDATE_STATE_APPLYING, consts.SW_UPDATE_STATE_DELETING]:
            self.mock_db_api.reset_mock()
            self.mock_scheduler.reset_mock()

            db_api.sw_update_strategy_update(self.ctx, state=state)

            self.orchestrator_manager = orchestrator_manager.OrchestratorManager()

            self.mock_db_api.sw_update_strategy_get.assert_called_once()
            self.mock_scheduler.ThreadGroupManager().start.assert_called_once_with(
                self.orchestrator_manager.periodic_strategy_monitoring, strategy.type
            )
            self.mock_log.info.assert_called_with(
                f"({strategy.type}) An active strategy was found, restarting "
                "its monitoring",
            )

    def test_stop_succeeds(self):
        """Test stop succeeds"""

        self.orchestrator_manager.stop()

        self.mock_scheduler.ThreadGroupManager().stop.assert_called_once()


class BaseTestOrchestratorManagerStrategyCreate(BaseTestOrchestratorManager):
    """Base test class for strategy creation"""

    def setUp(self):
        super().setUp()

        self.subcloud1 = self._update_subcloud(
            self.subcloud1.id,
            group_id=self.sc_group3.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self._update_subcloud_status(self.subcloud1.id)

        self.subcloud2 = self._update_subcloud(
            self.subcloud2.id,
            group_id=self.sc_group3.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self._update_subcloud_status(self.subcloud2.id)

    def _create_request_payload(self, strategy_type, **kwargs):
        return {
            "type": strategy_type,
            "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max-parallel-subclouds": "2",
            "stop-on-failure": "true",
            "release_id": "stx-10.0.0",
            "state": consts.SW_UPDATE_STATE_INITIAL,
            **kwargs,
        }

    def _update_subcloud(self, subcloud_id, **kwargs):
        return db_api.subcloud_update(self.ctx, subcloud_id, **kwargs)

    def _update_subcloud_status(
        self,
        subcloud_id,
        endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
        sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
    ):
        return db_api.subcloud_status_update(
            self.ctx, subcloud_id, endpoint, sync_status
        )

    def _assert_strategy(self, response, group, payload):
        for key, expected in response.items():
            value = None

            if key in ["id", "created-at", "updated-at", "extra-args"]:
                continue
            elif key == "subcloud-apply-type" and group:
                key = "update_apply_type"

            if group:
                value = group.get(key.replace("-", "_"))

            if not value:
                value = payload.get(key)

            if isinstance(expected, bool):
                value = bool(value)
            elif isinstance(expected, int):
                value = int(value)

            self.assertEqual(expected, value)

    def _assert_database_calls(
        self,
        subcloud_name=False,
        group=True,
        group_name=False,
        count_invalid=True,
        get_all_valid=True,
        create=True,
    ):
        self.mock_db_api.sw_update_strategy_get.assert_called_once()

        if group:
            if group_name:
                self.mock_utils_db_api.subcloud_group_get.assert_not_called()
                self.mock_utils_db_api.subcloud_group_get_by_name.assert_called_once()
            else:
                self.mock_utils_db_api.subcloud_group_get.assert_called_once()
                self.mock_utils_db_api.subcloud_group_get_by_name.assert_not_called()

            self.mock_db_api.subcloud_get_by_name.assert_not_called()
        elif subcloud_name:
            self.mock_db_api.subcloud_get_by_name.assert_called_once()
            self.mock_utils_db_api.subcloud_group_get.assert_not_called()
            self.mock_utils_db_api.subcloud_group_get_by_name.assert_not_called()
        else:
            self.mock_db_api.subcloud_get_by_name.assert_not_called()
            self.mock_utils_db_api.subcloud_group_get.assert_not_called()
            self.mock_utils_db_api.subcloud_group_get_by_name.assert_not_called()

        db_count_invalid = self.mock_db_api.subcloud_count_invalid_for_strategy_type
        if count_invalid:
            db_count_invalid.assert_called_once()
        else:
            db_count_invalid.assert_not_called()

        db_get_all_valid = (
            self.mock_db_api.subcloud_get_all_valid_for_strategy_step_creation
        )
        if get_all_valid:
            db_get_all_valid.assert_called_once()
        else:
            db_get_all_valid.assert_not_called()

        # When a validation error occurs, the strategy should not be created, so the
        # associated database requests are not made.
        if create:
            self.mock_db_api.sw_update_strategy_create.assert_called_once()
            self.mock_db_api.strategy_step_bulk_create.assert_called_once()
            self.mock_db_api.subcloud_bulk_update_by_ids.assert_called_once()
        else:
            self.mock_db_api.sw_update_strategy_create.assert_not_called()
            self.mock_db_api.strategy_step_bulk_create.assert_not_called()
            self.mock_db_api.subcloud_bulk_update_by_ids.assert_not_called()


class TestOrchestratorManagerStrategyCreate(BaseTestOrchestratorManagerStrategyCreate):
    """Test class for the strategy creation"""

    def setUp(self):
        super().setUp()

        self.payload = self._create_request_payload(
            consts.SW_UPDATE_TYPE_SOFTWARE, release_id="stx-10.0.0"
        )

    def test_create_software_strategy_fails_without_subclouds(self):
        """Test create strategy fails without subclouds

        In this case, it will fail because there isn't a subcloud nor a subcloud group
        specified and all subclouds created are outside the default group.
        """

        db_api.subcloud_destroy(self.ctx, self.subcloud1.id)
        db_api.subcloud_destroy(self.ctx, self.subcloud2.id)

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.create_sw_update_strategy,
            self.ctx,
            payload=self.payload,
        )

        self.assertEqual(
            str(exception), "Bad strategy request: Strategy has no steps to apply"
        )

    def test_create_software_strategy_fails_with_existing_strategy(self):
        """Test create software strategy fails with existing strategy"""

        strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
            consts.SW_UPDATE_STATE_INITIAL,
        )

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.create_sw_update_strategy,
            self.ctx,
            payload=self.payload,
        )

        self.assertEqual(
            str(exception),
            f"Bad strategy request: Strategy of type: '{strategy.type}' already exists",
        )


class TestOrchestratorManagerKubeRootcaCreate(
    BaseTestOrchestratorManagerStrategyCreate
):
    """Test class for the kube-rootca creation"""

    def setUp(self):
        super().setUp()

        extra_args = {"cert-file": "temp.ca"}
        self.payload = self._create_request_payload(
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE, **extra_args
        )

        for id in [self.subcloud1.id, self.subcloud2.id]:
            self._update_subcloud_status(
                id,
                dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            )

        self.mock_os = self._mock_object(orchestrator_manager, "os")
        self._mock_object(orchestrator_manager, "shutil")

    def test_kube_rootca_strategy_create_succeeds_with_cert_file(self):
        """Test kube-rootca strategy create succeeds with cert file"""

        cert_path = f"{consts.CERTS_VAULT_DIR}/{self.payload['cert-file']}"
        self.mock_os.path.join.return_value = cert_path

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, self.payload
        )

        self._assert_strategy(response, None, self.payload)
        self.assertEqual(response["extra-args"]["cert-file"], cert_path)
        self._assert_database_calls(group=False)

        # Verify strategy step was created as expected
        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(len(strategy_steps), 2)


class TestOrchestratorManagerSoftwareStrategyCreate(
    BaseTestOrchestratorManagerStrategyCreate
):
    """Test class for the software strategy creation"""

    def setUp(self):
        super().setUp()

        self.payload = self._create_request_payload(
            consts.SW_UPDATE_TYPE_SOFTWARE, release_id="stx-10.0.0"
        )

    def test_sw_strategy_create_succeeds_with_sw_deploy_and_subcloud_group(self):
        """Test create strategy succeeds with software deploy and subcloud group

        Subcloud1 is orchestrated, but subcloud2 is not, since it's not managed
        """

        self.subcloud1 = self._update_subcloud(
            self.subcloud1.id, group_id=self.sc_group2.id
        )
        self.subcloud2 = self._update_subcloud(
            self.subcloud2.id,
            group_id=self.sc_group2.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.payload["subcloud_group"] = str(self.subcloud1.group_id)
        del self.payload["subcloud-apply-type"]
        del self.payload["max-parallel-subclouds"]
        utils.validate_strategy_payload(self.ctx, self.payload)

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, self.payload
        )

        # Verify strategy was created as expected using group values
        # In this case, because the strategy apply type is serial, the
        # max_parallel_subclouds should be set to 1.
        self.sc_group2.max_parallel_subclouds = 1
        self._assert_strategy(response, self.sc_group2, self.payload)
        self._assert_database_calls()

        # Verify strategy step was created as expected
        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(len(strategy_steps), 1)
        self.assertEqual(strategy_steps[0]["state"], consts.STRATEGY_STATE_INITIAL)
        self.assertEqual(strategy_steps[0]["details"], "")
        self.assertEqual(strategy_steps[0]["subcloud_id"], 1)

    def test_sw_strategy_create_succeeds_with_parallel_apply_for_subcloud_group(self):
        """Test create strategy succeeds with parallel apply for subcloud group"""

        self.payload["subcloud_group"] = str(self.subcloud1.group_id)
        del self.payload["subcloud-apply-type"]
        del self.payload["max-parallel-subclouds"]
        utils.validate_strategy_payload(self.ctx, self.payload)

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, payload=self.payload
        )

        # Verify strategy was created as expected using group values
        self._assert_strategy(response, self.sc_group3, self.payload)
        self._assert_database_calls()
        self.assertEqual(len(db_api.strategy_step_get_all(self.ctx)), 2)

    def test_sw_strategy_create_succeeds_with_multiple_sync_status(self):
        """Test create strategy succeeds with multiple sync status

        Subcloud 1 is in-sync                   -> Not orchestrated
        Subcloud 2 does not have a sync status  -> Not orchestrated
        Subcloud 3 is out-of-sync               -> Orchestrated
        Subcloud 4 is not managed               -> Not orchestrated
        Subcloud 5 is offline                   -> Not orchestrated
        """

        fake_subcloud.create_fake_subcloud(self.ctx, name="subcloud4")
        fake_subcloud.create_fake_subcloud(self.ctx, name="subcloud5")

        update_values = [
            (dccommon_consts.MANAGEMENT_MANAGED, dccommon_consts.AVAILABILITY_ONLINE),
            (dccommon_consts.MANAGEMENT_UNMANAGED, dccommon_consts.AVAILABILITY_ONLINE),
            (dccommon_consts.MANAGEMENT_MANAGED, dccommon_consts.AVAILABILITY_OFFLINE),
        ]

        for index, values in enumerate(update_values, start=3):
            self._update_subcloud(
                index, management_state=values[0], availability_status=values[1]
            )

        sync_statuses = [
            dccommon_consts.SYNC_STATUS_IN_SYNC,
            None,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        ]

        for index, sync_status in enumerate(sync_statuses, start=1):
            self._update_subcloud_status(
                index, dccommon_consts.AUDIT_TYPE_SOFTWARE, sync_status
            )

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, payload=self.payload
        )

        # Verify strategy was created as expected using group values
        self._assert_strategy(response, None, self.payload)
        self._assert_database_calls(group=False)
        # The strategy is created only for the online, managed and out-of-sync subcloud
        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(len(strategy_steps), 1)
        self.assertEqual(strategy_steps[0].subcloud_id, 3)

    def test_sw_strategy_create_succeeds_without_subcloud_apply_type(self):
        """Test strategy create succeeds without subcloud apply type"""

        del self.payload["subcloud-apply-type"]

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, payload=self.payload
        )

        # Because the subcloud apply type was removed from the payload, it needs to be
        # re-added with the expected value in order for the validation to pass.
        self.payload["subcloud-apply-type"] = None
        self._assert_strategy(response, None, self.payload)
        self._assert_database_calls(group=False)
        self.assertEqual(len(db_api.strategy_step_get_all(self.ctx)), 2)

    def test_sw_strategy_create_succeeds_without_max_parallel_subclouds(self):
        """Test strategy create succeeds without max parallel subclouds"""

        del self.payload["max-parallel-subclouds"]
        utils.validate_strategy_payload(self.ctx, self.payload)

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, payload=self.payload
        )

        # Because the max parallel subclouds was removed from the payload, it needs
        # to be re-added with the expected value in order for the validation to pass.
        self.payload["max-parallel-subclouds"] = (
            consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS
        )
        self._assert_strategy(response, None, self.payload)
        self._assert_database_calls(group=False)
        self.assertEqual(len(db_api.strategy_step_get_all(self.ctx)), 2)

    def test_sw_strategy_create_fails_with_unknown_sync_status(self):
        """Test strategy create fails with unknown sync status"""

        self._update_subcloud_status(
            self.subcloud1.id,
            dccommon_consts.AUDIT_TYPE_SOFTWARE,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        )

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.create_sw_update_strategy,
            self.ctx,
            payload=self.payload,
        )

        self.assertEqual(
            str(exception),
            "Bad strategy request: software sync status is unknown for one or more "
            "subclouds",
        )
        self._assert_database_calls(group=False, get_all_valid=False, create=False)

    def test_sw_strategy_create_fails_with_subcloud_name_not_found(self):
        """Test strategy create fails with subcloud name not found"""

        self.payload["cloud_name"] = "subcloud5"

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.create_sw_update_strategy,
            self.ctx,
            payload=self.payload,
        )

        self.assertEqual(
            str(exception),
            f"Bad strategy request: Subcloud {self.payload['cloud_name']} does not "
            "exist",
        )
        self._assert_database_calls(
            subcloud_name=True,
            group=False,
            count_invalid=False,
            get_all_valid=False,
            create=False,
        )

    def test_sw_strategy_create_fails_with_subcloud_offline_and_in_sync(self):
        """Test strategy create fails with subcloud offline and in-sync"""

        self._update_subcloud(
            self.subcloud1.id, availability_status=dccommon_consts.AVAILABILITY_OFFLINE
        )
        self._update_subcloud_status(
            self.subcloud1.id,
            endpoint=dccommon_consts.AUDIT_TYPE_SOFTWARE,
            sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC,
        )

        self.payload["cloud_name"] = self.subcloud1.name

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.create_sw_update_strategy,
            self.ctx,
            payload=self.payload,
        )

        self.assertEqual(
            str(exception),
            f"Bad strategy request: Subcloud {self.payload['cloud_name']} does not "
            "require software update",
        )
        self._assert_database_calls(
            subcloud_name=True,
            group=False,
            count_invalid=False,
            get_all_valid=False,
            create=False,
        )


class TestOrchestratorManagerPrestageStrategyCreate(
    BaseTestOrchestratorManagerStrategyCreate
):
    """Test class for the prestage strategy creation"""

    def setUp(self):
        super().setUp()

        self._update_subcloud(
            self.subcloud1.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            prestage_status=consts.PRESTAGE_STATE_COMPLETE,
        )
        self._update_subcloud(
            self.subcloud2.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            prestage_status=consts.PRESTAGE_STATE_COMPLETE,
        )

        # Mock prestage methods
        mock_get_sc_deploy = self._mock_object(utils, "get_system_controller_deploy")
        mock_get_sc_deploy.return_value = None

        self.payload = self._create_request_payload(
            consts.SW_UPDATE_TYPE_PRESTAGE, force="false"
        )
        self.payload["sysadmin_password"] = self._create_password()

    def test_prestage_strategy_create_succeeds(self):
        """Test creating a prestage strategy succeeds"""

        self.payload["subcloud_group"] = self.sc_group3.name
        del self.payload["subcloud-apply-type"]
        del self.payload["max-parallel-subclouds"]
        utils.validate_strategy_payload(self.ctx, self.payload)

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, payload=self.payload
        )

        # Verify strategy was created as expected using group values
        self._assert_strategy(response, self.sc_group3, self.payload)
        self._assert_database_calls(count_invalid=False, group=True, group_name=True)
        self.assertEqual(len(db_api.strategy_step_get_all(self.ctx)), 2)

    def test_prestage_strategy_create_fails_with_subcloud_backup_in_progress(self):
        """Test create prestage strategy fails with subcloud backup in progress"""

        self._update_subcloud(
            self.subcloud1.id, backup_status=consts.BACKUP_STATE_IN_PROGRESS
        )

        self.payload["cloud_name"] = "subcloud1"

        self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.create_sw_update_strategy,
            self.ctx,
            payload=self.payload,
        )

    def test_prestage_strategy_create_succeeds_with_multiple_status(self):
        """Test strategy succeeds with multiple status

        Subcloud 1 is managed and online    -> Prestaged
        Subcloud 2 is unmanaged and online  -> Not prestaged
        Subcloud 3 is managed and offline   -> Not prestaged
        """

        self._update_subcloud(
            self.subcloud2.id, management_state=dccommon_consts.MANAGEMENT_UNMANAGED
        )
        self._update_subcloud(
            self.subcloud3.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
        )

        self.payload[consts.PRESTAGE_REQUEST_RELEASE] = "24.09"

        response = self.orchestrator_manager.create_sw_update_strategy(
            self.ctx, payload=self.payload
        )

        # Verify strategy was created as expected using group values
        self._assert_strategy(response, None, self.payload)
        self.assertEqual(
            self.payload[consts.PRESTAGE_REQUEST_RELEASE],
            response["extra-args"][consts.PRESTAGE_SOFTWARE_VERSION],
        )
        self._assert_database_calls(group=False, count_invalid=False)

        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(len(strategy_steps), 1)
        self.assertEqual(strategy_steps[0].subcloud_id, self.subcloud1.id)


class TestOrchestratorManagerStrategyDelete(BaseTestOrchestratorManager):
    """Test class for the strategy deletion"""

    def setUp(self):
        super().setUp()

        fake_strategy.create_fake_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )
        self.strategy_step1 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud1.id, consts.STRATEGY_STATE_COMPLETE
        )
        self.strategy_step2 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud2.id
        )

    def test_delete_strategy_succeeds_with_finished_steps(self):
        """Test delete strategy succeeds"""

        strategy = self.orchestrator_manager.delete_sw_update_strategy(self.ctx)

        self.assertEqual(strategy["state"], consts.SW_UPDATE_STATE_DELETING)
        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_called_once()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_called_once()
        self.mock_db_api.strategy_step_destroy_all.assert_called_once()
        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.sw_update_strategy_destroy.assert_not_called()
        self.mock_scheduler.ThreadGroupManager().start.assert_called_once_with(
            self.orchestrator_manager.periodic_strategy_monitoring, strategy["type"]
        )
        self.mock_log.info.assert_called_with(
            f"({strategy['type']}) Subcloud orchestration delete triggered"
        )

    def test_delete_strategy_succeeds_with_steps_in_initial_or_aborted(self):
        """Test delete strategy succeeds with steps in initial or aborted

        When all the strategy steps are in initial or aborted state, there is no
        need to delete the vim client in the subclouds. Therefore, both the steps
        and strategy are removed directly.
        """

        db_api.strategy_step_update(
            self.ctx, self.subcloud1.id, state=consts.STRATEGY_STATE_ABORTED
        )
        strategy = self.orchestrator_manager.delete_sw_update_strategy(self.ctx)

        self.assertEqual(strategy["state"], consts.SW_UPDATE_STATE_DELETING)
        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_called_once()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_called_once()
        self.mock_db_api.strategy_step_destroy_all.assert_called_once()
        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.sw_update_strategy_destroy.assert_called_once()
        self.mock_scheduler.ThreadGroupManager().start.assert_not_called()
        self.mock_log.info.assert_called_with(
            f"({strategy['type']}) Subcloud orchestration deleted"
        )

    def test_delete_strategy_fails_with_applying_state(self):
        """Test delete strategy fails with applying state"""

        strategy = self.orchestrator_manager.apply_sw_update_strategy(self.ctx)
        self.mock_db_api.reset_mock()
        self.mock_scheduler.reset_mock()
        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.delete_sw_update_strategy,
            self.ctx,
        )

        self.assertEqual(
            str(exception),
            f"Bad strategy request: Strategy in state {strategy['state']} cannot be "
            "deleted",
        )
        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_not_called()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_not_called()
        self.mock_db_api.strategy_step_destroy_all.assert_not_called()
        self.mock_db_api.strategy_step_get_all.assert_not_called()
        self.mock_db_api.sw_update_strategy_destroy.assert_not_called()
        self.mock_scheduler.ThreadGroupManager().start.assert_not_called()


class TestOrchestratorManagerStrategyApply(BaseTestOrchestratorManager):
    """Test class for the strategy application"""

    def setUp(self):
        super().setUp()

        fake_strategy.create_fake_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, consts.SW_UPDATE_STATE_INITIAL
        )
        fake_strategy.create_fake_strategy_step(self.ctx)

    def test_strategy_apply_succeeds(self):
        """Test strategy apply succeeds"""

        strategy = self.orchestrator_manager.apply_sw_update_strategy(self.ctx)

        self.assertEqual(strategy["state"], consts.SW_UPDATE_STATE_APPLYING)
        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_called_once()
        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_called_once()

    def test_strategy_apply_fails_with_invalid_strategy_state(self):
        """Test strategy apply fails with invalid strategy state"""

        strategy = self.orchestrator_manager.apply_sw_update_strategy(self.ctx)
        self.mock_db_api.reset_mock()

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.apply_sw_update_strategy,
            self.ctx,
        )
        self.assertEqual(
            str(exception),
            f"Bad strategy request: Strategy in state {strategy['state']} cannot be "
            "applied",
        )
        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_not_called()
        self.mock_db_api.strategy_step_get_all.assert_not_called()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_not_called()


class TestOrchestratorManagerStrategyAbort(BaseTestOrchestratorManager):
    """Test class for the strategy abortion"""

    def setUp(self):
        super().setUp()

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            consts.SW_UPDATE_TYPE_SOFTWARE,
            consts.SW_UPDATE_STATE_INITIAL,
            max_parallel_subclouds=1,
        )
        self.strategy_step1 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud1.id, state=consts.STRATEGY_STATE_COMPLETE
        )
        self.strategy_step2 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud2.id
        )
        self.strategy_step3 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud3.id
        )

    def test_strategy_abort_succeeds(self):
        """Test strategy abort succeeds

        When some of the strategy steps have already completed, they should have their
        state preserved, only setting to aborted the steps that are in initial state
        and that were sent to the workers or that are still waiting to be processed.
        """

        self.orchestrator_manager.apply_sw_update_strategy(self.ctx)
        self.mock_db_api.reset_mock()

        strategy = self.orchestrator_manager.abort_sw_update_strategy(self.ctx)

        self.assertEqual(strategy["state"], consts.SW_UPDATE_STATE_ABORT_REQUESTED)
        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_called_once()
        self.mock_db_api.strategy_step_abort_all_not_processing.assert_called_once()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_called_once()

        # The first subcloud should remain in complete state as it was already
        # processed. The second subcloud would be processing in the worker, so it should
        # remain in initial state until the worker processes it. The third subcloud,
        # because it is outside the max_parallel_subclouds range, should not be in any
        # of the workers, so it should be set to aborted.

        strategy_steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(strategy_steps[0].state, consts.STRATEGY_STATE_COMPLETE)
        self.assertEqual(strategy_steps[1].state, consts.STRATEGY_STATE_INITIAL)
        self.assertEqual(strategy_steps[2].state, consts.STRATEGY_STATE_ABORTED)

    def test_strategy_abort_fails_with_invalid_strategy_state(self):
        """Test strategy abort fails with invalid strategy state"""

        exception = self.assertRaises(
            exceptions.BadRequest,
            self.orchestrator_manager.abort_sw_update_strategy,
            self.ctx,
        )
        self.assertEqual(
            str(exception),
            f"Bad strategy request: Strategy in state {self.strategy['state']} cannot "
            "be aborted",
        )

        self.mock_db_api.sw_update_strategy_get.assert_called_once()
        self.mock_db_api.sw_update_strategy_update.assert_not_called()
        self.mock_db_api.strategy_step_abort_all_not_processing.assert_not_called()
        self.mock_db_api.sw_update_strategy_db_model_to_dict.assert_not_called()


class TestOrchestratorManagerStrategyMonitoringThread(BaseTestOrchestratorManager):
    """Test class for the strategy monitoring thread"""

    def setUp(self):
        super().setUp()

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            consts.SW_UPDATE_TYPE_SOFTWARE,
            consts.SW_UPDATE_STATE_INITIAL,
            max_parallel_subclouds=1,
        )

        self.mock_greenthread = self._mock_object(eventlet, "greenthread")
        self.orchestrator_manager._periodic_strategy_monitoring_loop = mock.MagicMock()
        self._monitoring_loop = (
            self.orchestrator_manager._periodic_strategy_monitoring_loop
        )

    def test_periodic_monitoring_thread_succeeds(self):
        """Test periodic monitoring thread succeeds"""

        self.mock_greenthread.sleep.side_effect = [
            None,
            eventlet.greenlet.GreenletExit(),
        ]

        self.orchestrator_manager.periodic_strategy_monitoring(self.strategy.type)

        self.mock_log.exception.assert_not_called()
        self._monitoring_loop.assert_called_once()

    def _stop_strategy(self, strategy_type):
        self.orchestrator_manager._monitor_strategy = False

    def test_periodic_monitoring_thread_succeeds_with_monitor_stopped(self):
        """Test periodic monitoring thread succeeds with monitor stop"""

        self.mock_greenthread.sleep.side_effect = [
            None,
            eventlet.greenlet.GreenletExit(),
        ]

        self._monitoring_loop.side_effect = self._stop_strategy

        self.orchestrator_manager.periodic_strategy_monitoring(self.strategy.type)

        self.mock_log.exception.assert_not_called()
        self._monitoring_loop.assert_called_once()

    def test_periodic_monitoring_thread_fails_with_strategy_not_found(self):
        """Test periodic monitoring thread fails with strategy not found"""

        self.mock_greenthread.sleep.side_effect = [
            None,
            eventlet.greenlet.GreenletExit(),
        ]
        self._monitoring_loop.side_effect = exceptions.StrategyNotFound()

        self.orchestrator_manager.periodic_strategy_monitoring(self.strategy.type)

        self.mock_log.exception.assert_called_with(
            f"({self.strategy.type}) The strategy does not exist anymore, "
            "stopping monitoring"
        )

    def test_periodic_monitoring_thread_fails_with_generic_exception(self):
        """Test periodic monitoring thread fails with generic exception"""

        self.mock_greenthread.sleep.side_effect = [
            None,
            eventlet.greenlet.GreenletExit(),
        ]

        self._monitoring_loop.side_effect = Exception("fake")

        self.orchestrator_manager.periodic_strategy_monitoring(self.strategy.type)

        self.mock_log.exception.assert_called_with(
            f"({self.strategy.type}) An error occurred in the strategy "
            "monitoring loop"
        )


class TestOrchestratorManagerStrategyMonitoring(BaseTestOrchestratorManager):
    """Test class for the strategy monitoring"""

    def setUp(self):
        super().setUp()

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE,
            consts.SW_UPDATE_STATE_INITIAL,
            max_parallel_subclouds=1,
        )

        self.strategy_step1 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud1.id
        )
        self.strategy_step2 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud2.id
        )
        self.strategy_step3 = fake_strategy.create_fake_strategy_step(
            self.ctx, self.subcloud3.id
        )

        # Because the periodic monitoring loop is not called, the monitor flag needs to
        # be manually set
        self.orchestrator_manager._monitor_strategy = True
        self.orchestrator_manager.delete_start_at = (
            timeutils.utcnow() - datetime.timedelta(minutes=1)
        )

    def test_stop_strategy_succeeds(self):
        """Test stop strategy succeeds"""

        self.orchestrator_manager.stop_strategy(self.strategy.type)

        self.mock_rpc_orchestrator_worker().stop_processing.assert_called_once()
        self.mock_log.info.assert_called_once_with(
            f"({self.strategy.type}) A request to stop the strategy was performed"
        )

        strategy = db_api.sw_update_strategy_get(self.ctx)
        self.assertEqual(strategy.state, consts.SW_UPDATE_STATE_FAILED)

    def test_monitoring_for_active_strategy_with_pending_steps(self):
        """Test monitoring for applying strategy with pending steps

        When the strategy is in an acitve state and can process more steps, the periodic
        monitoring will identify and send more steps to execute.
        """

        db_api.strategy_step_update_all(
            self.ctx,
            {},
            {"updated_at": timeutils.utcnow() - datetime.timedelta(minutes=2)},
        )

        states = [
            consts.SW_UPDATE_STATE_APPLYING,
            consts.SW_UPDATE_STATE_ABORTING,
            consts.SW_UPDATE_STATE_ABORT_REQUESTED,
        ]

        for state in states:
            self.strategy = db_api.sw_update_strategy_update(self.ctx, state=state)

            self.orchestrator_manager._periodic_strategy_monitoring_loop(
                self.strategy.type
            )

            calls = [
                mock.call.info(
                    f"({self.strategy.type}) 1 pending steps were found, start "
                    "processing"
                ),
                mock.call.info(
                    f"({self.strategy.type}) Sending 1 steps to orchestrate"
                ),
                mock.call.info(
                    f"({self.strategy.type}) Finished sending steps to orchestrate"
                ),
            ]
            self.mock_log.info.assert_has_calls(calls)
            self.mock_rpc_orchestrator_worker().orchestrate.assert_called_once()

            self.mock_log.reset_mock()
            self.mock_rpc_orchestrator_worker.reset_mock()

    def _test_monitoring_for_active_strategy_without_pending_steps(
        self, entries, expected_state
    ):
        """Test helper to set up the different scenarios and assert them"""

        self.mock_db_api.reset_mock()
        self.mock_rpc_audit.reset_mock()

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_APPLYING
        )
        db_api.strategy_step_bulk_update(self.ctx, entries)

        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        self.mock_db_api.sw_update_strategy_update.assert_called_once_with(
            self.ctx, update_type=self.strategy.type, state=expected_state
        )
        self.mock_rpc_audit().trigger_kube_rootca_update_audit.assert_called_once()
        self.assertFalse(self.orchestrator_manager._monitor_strategy)

    def test_monitoring_for_active_strategy_without_pending_steps(self):
        """Test monitoring for active strategy without pending steps

        When the strategy is in active state and there isn't any pending steps to
        process, the state of all steps will be retrieved from the database and, if
        applicable, the strategy will be updated to a finished state, i.e. failed,
        aborted or complete
        """

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_APPLYING
        )
        # Reset the updated_at field in strategy steps to avoid having them identified
        # as pending
        db_api.strategy_step_update_reset_updated_at(
            self.ctx,
            [self.subcloud1.id, self.subcloud2.id, self.subcloud3.id],
            timeutils.utcnow(),
        )

        # If all steps are in initial or any applying state, nothing will be done
        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        self.mock_db_api.sw_update_strategy_update.assert_not_called()
        self.mock_rpc_audit().trigger_kube_rootca_update_audit.assert_not_called()
        self.assertTrue(self.orchestrator_manager._monitor_strategy)

        # When all steps are in a finished state and at least one of them failed, the
        # strategy is set to failed
        entries = [
            {"id": self.subcloud1.id, "state": consts.STRATEGY_STATE_FAILED},
            {"id": self.subcloud2.id, "state": consts.STRATEGY_STATE_ABORTED},
            {"id": self.subcloud3.id, "state": consts.STRATEGY_STATE_COMPLETE},
        ]
        self._test_monitoring_for_active_strategy_without_pending_steps(
            entries, consts.SW_UPDATE_STATE_FAILED
        )

        # When all steps are in a finished state without any failures, but at least one
        # step is aborted, the strategy is set to aborted
        entries = [{"id": self.subcloud1.id, "state": consts.STRATEGY_STATE_COMPLETE}]
        self._test_monitoring_for_active_strategy_without_pending_steps(
            entries, consts.SW_UPDATE_STATE_ABORTED
        )

        # When all steps are in a finished state and completed, the strategy is set to
        # complete
        entries = [{"id": self.subcloud2.id, "state": consts.STRATEGY_STATE_COMPLETE}]
        self._test_monitoring_for_active_strategy_without_pending_steps(
            entries, consts.SW_UPDATE_STATE_COMPLETE
        )

    def test_monitoring_for_failed_strategy_with_stop_on_failure_set(self):
        """Test monitoring for failed strategy with stop on failure set

        When a strategy step fails and the strategy has the stop_on_failure flag set,
        the worker will send a request to the manager to set the strategy state to
        failed, in which case the monitor will identify the change, request the audit
        for the specific endpoint and stop the monitoring.
        """

        db_api.sw_update_strategy_update(self.ctx, state=consts.SW_UPDATE_STATE_FAILED)
        entries = [
            {"id": self.subcloud1.id, "state": consts.STRATEGY_STATE_INITIAL},
            {"id": self.subcloud2.id, "state": consts.STRATEGY_STATE_FAILED},
            {"id": self.subcloud3.id, "state": consts.STRATEGY_STATE_COMPLETE},
        ]
        db_api.strategy_step_bulk_update(self.ctx, entries)

        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        self.mock_rpc_audit().trigger_kube_rootca_update_audit.assert_called_once()
        self.assertFalse(self.orchestrator_manager._monitor_strategy)

    def test_monitoring_for_abort_requested_strategy_with_processing_steps(self):
        """Test monitoring for abort requested strategy with processing steps

        When the strategy is in abort requested and there isn't any pending steps
        identified, the monitoring will check if there is any step in initial state
        before updating the strategy to aborting.
        """

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_ABORT_REQUESTED
        )
        # Reset the updated_at field in strategy steps to avoid having them identified
        # as pending
        db_api.strategy_step_update_reset_updated_at(
            self.ctx,
            [self.subcloud1.id, self.subcloud2.id, self.subcloud3.id],
            timeutils.utcnow(),
        )

        # When one or more steps are in initial state, the strategy is not updated
        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        self.mock_db_api.sw_update_strategy_update.assert_not_called()

        # When there isn't any step in initial state, the strategy is set to aborting
        db_api.strategy_step_update_all(
            self.ctx, {}, {"state": consts.STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START}
        )

        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        self.mock_db_api.sw_update_strategy_update.assert_called_once_with(
            self.ctx,
            update_type=self.strategy.type,
            state=consts.SW_UPDATE_STATE_ABORTING,
        )

    def test_monitoring_for_deleting_strategy_with_pending_steps(self):
        """Test monitoring for deleting strategy with pending steps

        When the strategy is in deleting state and there are pending steps, the
        monitoring loop will identify them and send them to the workers for processing.
        """

        # Recreate the strategy with a different max_parallel_subclouds to test the
        # execution of a smaller request to the worker
        db_api.sw_update_strategy_destroy(self.ctx)
        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx,
            consts.SW_UPDATE_TYPE_SOFTWARE,
            consts.SW_UPDATE_STATE_DELETING,
            max_parallel_subclouds=3,
        )

        db_api.strategy_step_update_all(
            self.ctx,
            {},
            {"updated_at": timeutils.utcnow() - datetime.timedelta(minutes=2)},
        )

        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        calls = [
            mock.call.info(
                f"({self.strategy.type}) 3 pending steps were found, start processing"
            ),
            mock.call.info(f"({self.strategy.type}) Sending 2 steps to orchestrate"),
            mock.call.info(f"({self.strategy.type}) Sending 1 steps to orchestrate"),
            mock.call.info(
                f"({self.strategy.type}) Finished sending steps to orchestrate"
            ),
        ]
        self.mock_log.info.assert_has_calls(calls)
        self.mock_db_api.sw_update_strategy_destroy.assert_not_called()
        self.assertTrue(self.orchestrator_manager._monitor_strategy)

    def test_monitoring_for_deleting_strategy_without_pending_steps(self):
        """Test monitoring for deleting strategy without pending steps

        When the strategy is in deleting state and there aren't pending steps, the loop
        will move to its next execution until a new pending step is identified or the
        existing steps are deleted from the database.
        """

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_DELETING
        )
        # Reset the updated_at field in strategy steps to avoid having them identified
        # as pending
        db_api.strategy_step_update_reset_updated_at(
            self.ctx,
            [self.subcloud1.id, self.subcloud2.id, self.subcloud3.id],
            timeutils.utcnow(),
        )

        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        # When there are still steps in the database, but none of them are pending,
        # the execution just quits.
        self.mock_log.info.assert_not_called()
        self.mock_db_api.sw_update_strategy_destroy.assert_not_called()
        self.assertTrue(self.orchestrator_manager._monitor_strategy)

    def test_monitoring_for_deleting_strategy_without_steps(self):
        """Test monitoring for deleting strategy without steps

        When the strategy is in deleting state and there isn't any strategy steps in
        the database, the monitoring loop should delete the strategy.
        """

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_DELETING
        )
        db_api.strategy_step_destroy_all(self.ctx)

        self.orchestrator_manager._periodic_strategy_monitoring_loop(self.strategy.type)

        calls = [mock.call.info(f"({self.strategy.type}) Subcloud strategy deleted")]
        self.mock_log.info.assert_has_calls(calls)
        self.mock_db_api.sw_update_strategy_destroy.assert_called_once_with(
            self.ctx, self.strategy.type
        )
        self.assertFalse(self.orchestrator_manager._monitor_strategy)
