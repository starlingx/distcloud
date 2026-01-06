#
# Copyright (c) 2020-2022, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.firmware import finishing_fw_update
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.firmware.test_base import (
    TestFwUpdateState,
)

VENDOR_ID = "1"
DEVICE_ID = "2"


@mock.patch.object(finishing_fw_update, "DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch.object(finishing_fw_update, "DEFAULT_FAILED_SLEEP", 1)
class TestFwUpdateFinishingFwUpdateStage(TestFwUpdateState):
    def setUp(self):
        super().setUp()

        self._mock_object(rpc_client, "SubcloudStateClient")

        # set the next state in the chain (when this state is successful)
        self.on_success_state = consts.STRATEGY_STATE_COMPLETE
        self.current_state = consts.STRATEGY_STATE_FINISHING_FW_UPDATE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, self.current_state
        )

        # Create fake variables to be used in sysinv_client methods
        self.fake_host = FakeController()

        self.fake_device = self._create_fake_device(VENDOR_ID, DEVICE_ID)

        self.fake_device_image = self._create_fake_device_image(
            VENDOR_ID, DEVICE_ID, True, {}
        )

        self.fake_device_image_state = self._create_fake_device_image_state(
            self.fake_device.uuid, self.fake_device_image.uuid, "completed"
        )

    def test_finishing_vim_strategy_success(self):
        """Test finishing the firmware update.

        In this case, there aren't enabled host devices, leaving the execution early
        """

        # this tests successful steps of:
        # - vim strategy exists on subcloud and can be deleted
        # - no device image states on the subcloud are 'failed'
        self.vim_client.get_strategy.return_value = self._create_fake_strategy(
            vim.STATE_APPLIED
        )

        self._setup_and_assert(self.on_success_state)

    def test_finishing_vim_strategy_success_no_strategy(self):
        """Test finishing the firmware update.

        Finish the orchestration state when there is no subcloud vim strategy.
        """

        # this tests successful steps of:
        # - vim strategy does not exist for some reason
        # - no device image states on the subcloud are 'failed'
        self.vim_client.get_strategy.return_value = None

        self._setup_and_assert(self.on_success_state)

        # ensure that the delete was not called
        self.vim_client.delete_strategy.assert_not_called()

    def test_finishing_vim_strategy_failure_get_hosts(self):
        """Test finishing firmware update with communication error to subcloud"""

        # mock the get_host query fails and raises an exception
        self.sysinv_client.get_hosts.side_effect = Exception("HTTP CommunicationError")

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Timeout waiting to query subcloud hosts"
        )

        # verify the query was actually attempted
        self.sysinv_client.get_hosts.assert_called()

        # verified the query was tried max retries + 1
        self.assertEqual(
            finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1,
            self.sysinv_client.get_hosts.call_count,
        )

        # verify the subsequent sysinv command was never attempted
        self.sysinv_client.get_host_device_list.assert_not_called()

    @mock.patch.object(BaseState, "stopped", return_value=True)
    def test_finishing_fw_update_fails_when_strategy_stops(self, _):
        """Test finishing fw update fails when strategy stops before acquiring

        host device
        """

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: Strategy has been stopped")

    def test_finishing_fw_update_succeeds_with_enabled_host_device(self):
        """Test finishing fw update succeeds with an enabled host device"""

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]
        self.sysinv_client.get_device_images.return_value = [self.fake_device_image]
        self.sysinv_client.get_device_image_states.return_value = [
            self.fake_device_image_state
        ]

        self._setup_and_assert(self.on_success_state)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_called_once()
        self.sysinv_client.get_device_image_states.assert_called_once()

    def test_finishing_fw_update_succeeds_with_host_device_disabled(self):
        """Test finishing fw update succeeds with a device disabled"""
        self.fake_device.enabled = False

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]

        self._setup_and_assert(self.on_success_state)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_not_called()
        self.sysinv_client.get_device_image_states.assert_not_called()

    @mock.patch.object(BaseState, "stopped")
    def test_finishing_fw_update_fails_when_strategy_stops_with_enabled_host_device(
        self, mock_base_state
    ):
        """Test finishing fw update fails when strategy stops after acquiring

        host device
        """

        mock_base_state.side_effect = [False, True]

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: Strategy has been stopped")

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_not_called()
        self.sysinv_client.get_device_image_states.assert_not_called()

    def test_finishing_fw_update_fails_with_get_device_image_states_exception(self):
        """Test finishing fw update fails when get_device_image_states raises

        an Exception
        """

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]
        self.sysinv_client.get_device_images.return_value = [self.fake_device_image]
        self.sysinv_client.get_device_image_states.side_effect = Exception()

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(
            f"{self.current_state}: Timeout waiting to query subcloud device image info"
        )

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.assertEqual(
            self.sysinv_client.get_device_images.call_count,
            finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1,
        )
        # TODO(rlima): update the code to fix the error where the call_count is
        # always greater than the DEFAULT_MAX_FAILED_QUERIES
        self.assertEqual(
            self.sysinv_client.get_device_image_states.call_count,
            finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1,
        )

    def test_finishing_fw_update_fails_with_pending_image_state(self):
        """Test finishing fw update fails with pending image state

        In this scenarion, there are three failed image states in order to cover all
        possible outcomes in their validation:
        - The first is complete with the status pending
        - The second has the same status but its image is None
        - The third has the same status but rs device is None
        """

        self.fake_device_image_state.status = "pending"

        fake_device_image_state_with_image_none = self._create_fake_device_image_state(
            self.fake_device.uuid, None, "pending"
        )
        fake_device_image_state_with_device_none = self._create_fake_device_image_state(
            None, self.fake_device_image.uuid, "pending"
        )

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]
        self.sysinv_client.get_device_images.return_value = [self.fake_device_image]
        self.sysinv_client.get_device_image_states.return_value = [
            self.fake_device_image_state,
            fake_device_image_state_with_image_none,
            fake_device_image_state_with_device_none,
        ]

        self._setup_and_assert(consts.STRATEGY_STATE_FAILED)
        self._assert_error(f"{self.current_state}: Not all images applied successfully")

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_called_once()
        self.sysinv_client.get_device_image_states.assert_called_once()
