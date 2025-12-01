# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2017-2022, 2024-2025 Wind River Systems, Inc.
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

import http.client

from oslo_messaging import RemoteError

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator import rpcapi as rpc_client
from dcmanager.tests.unit.api.test_root_controller import DCManagerApiTest
from dcmanager.tests.unit.common import consts as fake_consts
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud


class BaseTestSwUpdateStrategyController(DCManagerApiTest):
    """Base class for testing the SwUpdateStrategyController"""

    def setUp(self):
        super().setUp()

        self.url = "/v1.0/sw-update-strategy"

        self.mock_rpc_orchestrator_client = self._mock_object(
            rpc_client, "ManagerOrchestratorClient"
        )


class TestSwUpdateStrategyController(BaseTestSwUpdateStrategyController):
    """Test class for SwUpdateStrategyController"""

    def setUp(self):
        super().setUp()

    def test_unmapped_method(self):
        """Test requesting an unmapped method results in success with null content"""

        self.method = self.app.put

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.text, "null")


class BaseTestSwUpdateStrategyGet(BaseTestSwUpdateStrategyController):
    """Base test class for get requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.get


class TestSwUpdateStrategyGet(BaseTestSwUpdateStrategyGet):
    """Test class for get requests"""

    def setUp(self):
        super().setUp()

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_FIRMWARE
        )

    def _assert_response_payload(self, response):
        self.assertEqual(response.json["type"], consts.SW_UPDATE_TYPE_FIRMWARE)
        self.assertEqual(response.json["state"], consts.SW_UPDATE_STATE_INITIAL)

    def test_get_succeeds(self):
        """Test get succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response)

    def test_get_succeeds_with_type(self):
        """Test get succeeds with type"""

        self.url = f"{self.url}?type={consts.SW_UPDATE_TYPE_FIRMWARE}"

        response = self._send_request()

        self._assert_response(response)
        self._assert_response_payload(response)

    def test_get_succeeds_with_invalid_verb(self):
        """Test get succeeds with invalid verb"""

        # TODO(rlima): when a get request is made with an invalid verb, the steps
        # variable from the controller is not mapped to a correct execution and,
        # therefore, it results in a successful response while it should've been
        # a bad request.

        self.url = f"{self.url}/fake"

        response = self._send_request()

        self._assert_response(response)

    def test_get_fails_with_db_api_not_found_exception(self):
        """Test get fails with db api not found exception"""

        db_api.sw_update_strategy_destroy(self.ctx)

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Strategy not found"
        )

    def test_get_fails_with_type_and_db_api_not_found_exception(self):
        """Test get fails with db api not found exception"""

        self.url = f"{self.url}?type={consts.SW_UPDATE_TYPE_FIRMWARE}"

        db_api.sw_update_strategy_destroy(self.ctx)

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.NOT_FOUND,
            f"Strategy of type '{consts.SW_UPDATE_TYPE_FIRMWARE}' not found",
        )


class TestSwUpdateStrategyGetSteps(BaseTestSwUpdateStrategyGet):
    """Test class for get requests with steps verb"""

    def setUp(self):
        super().setUp()

        self.url = f"{self.url}/steps"

        self.subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        self.strategy = fake_strategy.create_fake_strategy_step(
            self.ctx, state=consts.STRATEGY_STATE_INITIAL
        )

    def test_get_steps_succeeds(self):
        """Test get steps succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(
            response.json["strategy-steps"][0]["state"], consts.STRATEGY_STATE_INITIAL
        )

    def test_get_steps_succeeds_with_subcloud_name(self):
        """Test get steps succeeds with subcloud name"""

        self.url = f"{self.url}/{self.subcloud.name}"

        response = self._send_request()

        self._assert_response(response)
        self.assertEqual(response.json["cloud"], self.subcloud.name)

    def test_get_steps_fails_with_inexistent_subcloud(self):
        """Test get steps fails with inexistent subcloud"""

        self.url = f"{self.url}/fake_subcloud"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Strategy step not found"
        )

    def test_get_steps_fails_with_inexistent_strategy_for_system_controller(self):
        """Test get steps fails with inexistent strategy for system controller"""

        self.url = f"{self.url}/{dccommon_consts.SYSTEM_CONTROLLER_NAME}"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.NOT_FOUND, "Strategy step not found"
        )


class BaseTestSwUpdateStrategyPost(BaseTestSwUpdateStrategyController):
    """Base test class for post requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json

        self.params = {
            "type": consts.SW_UPDATE_TYPE_SOFTWARE,
            "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max-parallel-subclouds": "10",
            "stop-on-failure": "true",
            "release_id": fake_consts.RELEASE_ID,
        }

        self.mock_rpc_orchestrator_client().create_sw_update_strategy.return_value = (
            "create_sw_update_strategy",
            {"payload": self.params},
        )
        self.create_update_strategy = (
            self.mock_rpc_orchestrator_client().create_sw_update_strategy
        )
        self.mock_check_version_for_sw_deploy_strategy = self._mock_object(
            utils, "check_version_for_sw_deploy_strategy"
        )
        self.mock_get_system_controller_deploy = self._mock_object(
            utils, "get_system_controller_deploy"
        )
        self.mock_get_validated_sw_version_for_prestage = self._mock_object(
            utils, "get_validated_sw_version_for_prestage"
        )
        self.mock_check_version_for_sw_deploy_strategy.return_value = [
            True,
        ]


class TestSwUpdateStrategyPost(BaseTestSwUpdateStrategyPost):
    """Test class for post requests"""

    def test_post_succeeds(self):
        """Test post succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.create_update_strategy.assert_called_once()

    def test_post_fails_with_invalid_type(self):
        """Test post fails with invalid type"""

        self.params["type"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "type invalid"
        )
        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_invalid_subcloud_apply_type(self):
        """Test post fails with invalid subcloud apply type"""

        self.params["subcloud-apply-type"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "subcloud-apply-type invalid"
        )
        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_invalid_max_parallel_subclouds(self):
        """Test post fails with invalid max parallel subclouds"""

        invalid_values = ["fake", 5001, -2]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["max-parallel-subclouds"] = invalid_value

            response = self._send_request()
            default_error_msg = (
                f"Invalid max-parallel-subclouds value: {invalid_value}. "
                f"For {self.params.get('type')} strategy, the value must be between 1 "
                f"and {consts.MAX_PARALLEL_SUBCLOUDS_LIMIT}."
            )
            value_error_msg = (
                f"max-parallel-subclouds invalid value. Value: {invalid_value}"
            )

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                default_error_msg if invalid_value != "fake" else value_error_msg,
                call_count=index,
            )

        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_invalid_max_parallel_subclouds_prestage(self):
        """Test post fails with invalid max parallel subclouds"""

        invalid_value = 251

        self.params["max-parallel-subclouds"] = invalid_value
        self.params["with_prestage"] = True

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            (
                f"Invalid max-parallel-subclouds value: {invalid_value}. For prestage, "
                f"the value must be between 1 and {consts.MAX_PARALLEL_PRESTAGE_LIMIT}."
            ),
        )

        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_invalid_force_or_sysadmin_password(self):
        """Test post fails with invalid max parallel subclouds"""

        self.params["sysadmin_password"] = "fake_password"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            ("The with_prestage option is required when using sysadmin_password"),
        )

        self.create_update_strategy.assert_not_called()

    def test_prestage_strategy_create_fails_without_password(self):
        """Test create strategy fails for prestage without password"""

        self.params["sysadmin_password"] = ""
        self.params["type"] = consts.SW_UPDATE_TYPE_PRESTAGE
        self.mock_get_system_controller_deploy.return_value = None
        self.mock_get_validated_sw_version_for_prestage.return_value = ("25.09", "")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            "subcloud sysadmin_password required",
        )

        self.create_update_strategy.assert_not_called()

    def test_prestage_strategy_create_fails_release_deploying(self):
        """Test create strategy fails when software deployment is in progress"""

        self.params["sysadmin_password"] = ""
        self.params["type"] = consts.SW_UPDATE_TYPE_PRESTAGE
        self.mock_get_system_controller_deploy.return_value = "starlingx-25.09.1"
        self.mock_get_validated_sw_version_for_prestage.return_value = ("25.09", "")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            (
                "Prestage operations are not allowed while system controller "
                "has a software deployment in progress."
            ),
        )

        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_invalid_stop_on_failure(self):
        """Test post fails with invalid stop on failure"""

        invalid_values = [
            "fake",
        ]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["stop-on-failure"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "stop-on-failure invalid",
                call_count=index,
            )

        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_invalid_force(self):
        """Test post fails with invalid force"""

        self.params["force"] = "fake"

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.BAD_REQUEST,
            (
                f"Invalid value '{self.params['force']}' for force "
                "- must be True/False or 'true'/'false'"
            ),
        )
        self.create_update_strategy.assert_not_called()

    def test_succeed_using_subcloud_group_no_apply_type_and_max_parallel(self):
        """Test succeeds using subcloud group without apply type and max parallel"""

        self.params["subcloud_group"] = fake_subcloud.create_fake_subcloud_group(
            self.ctx, name="Group1", max_parallel_subclouds=5
        )

        del self.params["subcloud-apply-type"]
        del self.params["max-parallel-subclouds"]

        self.params["subcloud_group"] = "2"

        response = self._send_request()

        self._assert_response(response)
        self.create_update_strategy.assert_called_once()

    def test_post_fails_with_inexistent_subcloud_group_name(self):
        """Test post fails with inexistent subcloud group name"""

        del self.params["subcloud-apply-type"]
        del self.params["max-parallel-subclouds"]

        invalid_values = ["fake", "999"]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["subcloud_group"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response, http.client.BAD_REQUEST, "Invalid group_id", call_count=index
            )
            self.create_update_strategy.assert_not_called()

    def test_post_fails_with_cloud_name_and_subcloud_group(self):
        """Test post fails with cloud name and subcloud group"""

        del self.params["subcloud-apply-type"]
        del self.params["max-parallel-subclouds"]
        self.params["cloud_name"] = "subcloud1"

        invalid_values = ["group1", "999"]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["subcloud_group"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                "cloud_name and subcloud_group are mutually exclusive",
                call_count=index,
            )
            self.create_update_strategy.assert_not_called()

    def test_post_fails_with_subcloud_group_and_other_values(self):
        """Test post fails with subcloud group and other values

        The subcloud-apply-type and max-parallel-subclouds should not be used
        when subcloud_group is sent
        """

        invalid_values = ["group1", "999"]

        for index, invalid_value in enumerate(invalid_values, start=1):
            self.params["subcloud_group"] = invalid_value

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.BAD_REQUEST,
                (
                    "subcloud-apply-type and max-parallel-subclouds are not allowed "
                    "when subcloud_group is provided"
                ),
                call_count=index,
            )
            self.create_update_strategy.assert_not_called()

    def test_post_fails_without_params(self):
        """Test post fails without params"""

        self.params = {}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "Body required"
        )
        self.create_update_strategy.assert_not_called()

    def test_post_fails_without_type(self):
        """Test post fails without type"""

        del self.params["type"]

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "type required"
        )
        self.create_update_strategy.assert_not_called()

    def test_post_fails_with_rpc_remote_error(self):
        """Test post fails with rpc remote error"""

        self.create_update_strategy.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "Unable to create strategy "
            f"of type '{consts.SW_UPDATE_TYPE_SOFTWARE}': value",
        )
        self.create_update_strategy.assert_called_once()

    def test_post_fails_with_rpc_generic_exception(self):
        """Test post fails with rpc generic exception"""

        self.create_update_strategy.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to create strategy"
        )
        self.create_update_strategy.assert_called_once()


class TestSwUpdateStrategyPostSoftware(BaseTestSwUpdateStrategyPost):
    """Test class for post requests with software strategy"""

    RELEASE_ID_ERROR = "Release ID is required for strategy type: sw-deploy."
    SNAPSHOT_ERROR = (
        "Option snapshot cannot be used with any of the following options: "
        "rollback or delete_only."
    )
    WITH_DELETE_ERROR = (
        "Option with_delete cannot be used with any of the following options: "
        "rollback or delete_only."
    )
    ROLLBACK_ERROR = (
        "Option rollback cannot be used with any of the following options: "
        "release_id, delete_only or with_prestage."
    )

    def base_post_software_succeeds_extra_args(
        self,
        release_id=None,
        snapshot=None,
        rollback=None,
        with_delete=None,
        delete_only=None,
    ):
        """Base post test case of software strategy succeeds with extra args"""

        self.params = {
            "type": consts.SW_UPDATE_TYPE_SOFTWARE,
            "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max-parallel-subclouds": "10",
            "stop-on-failure": "true",
            consts.EXTRA_ARGS_RELEASE_ID: release_id,
            consts.EXTRA_ARGS_WITH_DELETE: with_delete,
            consts.EXTRA_ARGS_SNAPSHOT: snapshot,
            consts.EXTRA_ARGS_DELETE_ONLY: delete_only,
            consts.EXTRA_ARGS_ROLLBACK: rollback,
        }
        response = self._send_request()

        self._assert_response(response)
        self.create_update_strategy.assert_called_once()

    def base_post_software_fails_extra_args(
        self,
        error_msg,
        release_id=None,
        snapshot=None,
        rollback=None,
        with_delete=None,
        delete_only=None,
        with_prestage=None,
    ):
        """Base post test case of software strategy fails with extra args"""

        self.params = {
            "type": consts.SW_UPDATE_TYPE_SOFTWARE,
            "subcloud-apply-type": consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
            "max-parallel-subclouds": "10",
            "stop-on-failure": "true",
            consts.EXTRA_ARGS_RELEASE_ID: release_id,
            consts.EXTRA_ARGS_WITH_DELETE: with_delete,
            consts.EXTRA_ARGS_SNAPSHOT: snapshot,
            consts.EXTRA_ARGS_DELETE_ONLY: delete_only,
            consts.EXTRA_ARGS_ROLLBACK: rollback,
            consts.EXTRA_ARGS_WITH_PRESTAGE: with_prestage,
        }
        response = self._send_request()
        self._assert_pecan_and_response(response, http.client.BAD_REQUEST, error_msg)
        self.create_update_strategy.assert_not_called()

    def test_post_software_succeeds_with_delete(self):
        """Test post of software strategy succeeds with delete"""

        self.base_post_software_succeeds_extra_args(
            release_id=fake_consts.RELEASE_ID, with_delete=True
        )

    def test_post_software_succeeds_snapshot(self):
        """Test post of software strategy succeeds with snapshot"""

        self.base_post_software_succeeds_extra_args(
            release_id=fake_consts.RELEASE_ID, snapshot=True
        )

    def test_post_software_succeeds_with_delete_and_snapshot(self):
        """Test post of software strategy succeeds with_delete and snapshot"""

        self.base_post_software_succeeds_extra_args(
            release_id=fake_consts.RELEASE_ID,
            snapshot=True,
            with_delete=True,
        )

    def test_post_software_succeeds_rollback(self):
        """Test post of software strategy succeeds with rollback"""

        self.base_post_software_succeeds_extra_args(rollback=True)

    def test_post_software_succeeds_delete_only(self):
        """Test post of software strategy succeeds with delete_only"""

        self.base_post_software_succeeds_extra_args(delete_only=True)

    def test_post_software_fails_without_extra_args(self):
        """Test post of software strategy fails without extra args"""

        self.base_post_software_fails_extra_args(self.RELEASE_ID_ERROR)

    def test_post_software_fails_snapshot_and_rollback(self):
        """Test post of software strategy fails with snapshot and rollback"""

        self.base_post_software_fails_extra_args(
            self.SNAPSHOT_ERROR,
            release_id=fake_consts.RELEASE_ID,
            snapshot=True,
            rollback=True,
        )

    def test_post_software_fails_snapshot_and_delete_only(self):
        """Test post of software strategy fails with snapshot and delete_only"""

        self.base_post_software_fails_extra_args(
            self.SNAPSHOT_ERROR,
            release_id=fake_consts.RELEASE_ID,
            snapshot=True,
            delete_only=True,
        )

    def test_post_software_fails_with_delete_and_rollback(self):
        """Test post of software strategy fails with rollback and with_delete"""

        self.base_post_software_fails_extra_args(
            self.WITH_DELETE_ERROR,
            rollback=True,
            with_delete=True,
        )

    def test_post_software_fails_with_delete_and_delete_only(self):
        """Test post of software strategy fails with_delete and delete_only"""

        self.base_post_software_fails_extra_args(
            self.WITH_DELETE_ERROR,
            release_id=fake_consts.RELEASE_ID,
            with_delete=True,
            delete_only=True,
        )

    def test_post_software_fails_rollback_and_release(self):
        """Test post of software strategy fails with rollback and release"""

        self.base_post_software_fails_extra_args(
            self.ROLLBACK_ERROR,
            release_id=fake_consts.RELEASE_ID,
            rollback=True,
        )

    def test_post_software_fails_rollback_and_delete_only(self):
        """Test post of software strategy fails with rollback and delete_only"""

        self.base_post_software_fails_extra_args(
            self.ROLLBACK_ERROR,
            rollback=True,
            delete_only=True,
        )

    def test_post_software_fails_rollback_and_with_prestage(self):
        """Test post of software strategy fails with rollback and with_prestage"""

        self.base_post_software_fails_extra_args(
            self.ROLLBACK_ERROR,
            rollback=True,
            with_prestage=True,
        )


class TestSwUpdateStrategyPostActions(BaseTestSwUpdateStrategyController):
    """Test class for post requests with actions verb"""

    def setUp(self):
        super().setUp()

        self.method = self.app.post_json
        self.url = f"{self.url}/actions"

        self.mock_rpc_orchestrator_client().apply_sw_update_strategy.return_value = (
            "apply_sw_update_strategy",
            {"update_type": None},
        )
        self.mock_rpc_orchestrator_client().abort_sw_update_strategy.return_value = (
            "abort_sw_update_strategy",
            {"update_type": None},
        )
        self.apply_update_strate = (
            self.mock_rpc_orchestrator_client().apply_sw_update_strategy
        )
        self.abort_update_strategy = (
            self.mock_rpc_orchestrator_client().abort_sw_update_strategy
        )

    def test_post_actions_succeeds(self):
        """Test post actions succeeds"""

        actions = [consts.SW_UPDATE_ACTION_APPLY, consts.SW_UPDATE_ACTION_ABORT]

        for action in actions:
            self.params = {"action": action}

            response = self._send_request()

            self._assert_response(response)

        self.apply_update_strate.assert_called_once()
        self.abort_update_strategy.assert_called_once()

    def test_post_actions_succeeds_with_type(self):
        """Test post actions succeeds with type"""

        self.url = f"{self.url}?type={consts.SW_UPDATE_TYPE_FIRMWARE}"

        actions = [consts.SW_UPDATE_ACTION_APPLY, consts.SW_UPDATE_ACTION_ABORT]

        for action in actions:
            self.params = {"action": action}

            response = self._send_request()

            self._assert_response(response)

        self.apply_update_strate.assert_called_once()
        self.abort_update_strategy.assert_called_once()

    def test_post_actions_succeeds_with_inexistent_action(self):
        """Test post actions succeeds with inexistent action

        A post request with an inexistent action results in not executing it
        """

        self.params = {"action": "fake"}

        response = self._send_request()

        self._assert_response(response)
        self.apply_update_strate.assert_not_called()
        self.abort_update_strategy.assert_not_called()

    def test_post_actions_fails_without_action(self):
        """Test post actions fails without action"""

        self.params = {"key": "value"}

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.BAD_REQUEST, "action required"
        )
        self.apply_update_strate.assert_not_called()
        self.abort_update_strategy.assert_not_called()

    def test_post_actions_fails_with_rpc_remote_error(self):
        """Test post actions fails with rpc remote error"""

        self.apply_update_strate.side_effect = RemoteError("msg", "value")
        self.abort_update_strategy.side_effect = RemoteError("msg", "value")

        actions = [consts.SW_UPDATE_ACTION_APPLY, consts.SW_UPDATE_ACTION_ABORT]

        for index, action in enumerate(actions, start=1):
            self.params = {"action": action}

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.UNPROCESSABLE_ENTITY,
                f"Unable to {action} strategy of type 'None': value",
                call_count=index,
            )

        self.apply_update_strate.assert_called_once()
        self.abort_update_strategy.assert_called_once()

    def test_post_actions_fails_with_rpc_generic_exception(self):
        """Test post actions fails with rpc generic exception"""

        self.apply_update_strate.side_effect = Exception()
        self.abort_update_strategy.side_effect = Exception()

        actions = [consts.SW_UPDATE_ACTION_APPLY, consts.SW_UPDATE_ACTION_ABORT]

        for index, action in enumerate(actions, start=1):
            self.params = {"action": action}

            response = self._send_request()

            self._assert_pecan_and_response(
                response,
                http.client.INTERNAL_SERVER_ERROR,
                f"Unable to {action} strategy",
                call_count=index,
            )

        self.apply_update_strate.assert_called_once()
        self.abort_update_strategy.assert_called_once()


class TestSwUpdateStrategyDelete(BaseTestSwUpdateStrategyController):
    """Test class for delete requests"""

    def setUp(self):
        super().setUp()

        self.method = self.app.delete

        self.mock_rpc_orchestrator_client().delete_sw_update_strategy.return_value = (
            "delete_sw_update_strategy",
            {"update_type": None},
        )
        self.delete_update_strategy = (
            self.mock_rpc_orchestrator_client().delete_sw_update_strategy
        )

    def test_delete_succeeds(self):
        """Test delete succeeds"""

        response = self._send_request()

        self._assert_response(response)
        self.delete_update_strategy.assert_called_once()

    def test_delete_succeeds_with_type(self):
        """Test delete succeeds with type"""

        self.url = f"{self.url}?type={consts.SW_UPDATE_TYPE_FIRMWARE}"

        response = self._send_request()

        self._assert_response(response)
        self.delete_update_strategy.assert_called_once()

    def test_delete_fails_with_rpc_remote_error(self):
        """Test delete fails with rpc remote error"""

        self.delete_update_strategy.side_effect = RemoteError("msg", "value")

        response = self._send_request()

        self._assert_pecan_and_response(
            response,
            http.client.UNPROCESSABLE_ENTITY,
            "Unable to delete strategy of type 'None': value",
        )
        self.delete_update_strategy.assert_called_once()

    def test_delete_fails_with_rpc_generic_exception(self):
        """Test delete fails with rpc generic exception"""

        self.delete_update_strategy.side_effect = Exception()

        response = self._send_request()

        self._assert_pecan_and_response(
            response, http.client.INTERNAL_SERVER_ERROR, "Unable to delete strategy"
        )
        self.delete_update_strategy.assert_called_once()
