#
# Copyright (c) 2020-2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import mock

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.firmware import finishing_fw_update
from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.firmware.test_base \
    import TestFwUpdateState

VENDOR_ID = '1'
DEVICE_ID = '2'


@mock.patch("dcmanager.orchestrator.states.firmware."
            "finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.firmware."
            "finishing_fw_update.DEFAULT_FAILED_SLEEP", 1)
class TestFwUpdateFinishingFwUpdateStage(TestFwUpdateState):

    def setUp(self):
        super(TestFwUpdateFinishingFwUpdateStage, self).setUp()

        self._mock_rpc_subcloud_state_client()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = consts.STRATEGY_STATE_COMPLETE

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_FINISHING_FW_UPDATE
        )

        # Add mock API endpoints for sysinv client calls invocked by this state
        self.vim_client.get_strategy = mock.MagicMock()
        self.vim_client.delete_strategy = mock.MagicMock()
        self.sysinv_client.get_hosts = mock.MagicMock()
        self.sysinv_client.get_host_device_list = mock.MagicMock()
        self.sysinv_client.get_device_images = mock.MagicMock()
        self.sysinv_client.get_device_image_states = mock.MagicMock()

        # Create fake variables to be used in sysinv_client methods
        self.fake_host = FakeController()

        self.fake_device = self._create_fake_device(VENDOR_ID, DEVICE_ID)

        self.fake_device_image = self._create_fake_device_image(
            VENDOR_ID, DEVICE_ID, True, {}
        )

        self.fake_device_image_state = self._create_fake_device_image_state(
            self.fake_device.uuid,
            self.fake_device_image.uuid,
            'completed'
        )

    def test_finishing_vim_strategy_success(self):
        """Test finishing the firmware update.

        In this case, there aren't enabled host devices, leaving the execution early
        """

        # this tests successful steps of:
        # - vim strategy exists on subcloud and can be deleted
        # - no device image states on the subcloud are 'failed'
        self.vim_client.get_strategy.return_value = \
            self._create_fake_strategy(vim.STATE_APPLIED)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Successful promotion to next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_finishing_vim_strategy_success_no_strategy(self):
        """Test finishing the firmware update.

        Finish the orchestration state when there is no subcloud vim strategy.
        """

        # this tests successful steps of:
        # - vim strategy does not exist for some reason
        # - no device image states on the subcloud are 'failed'
        self.vim_client.get_strategy.return_value = None

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # ensure that the delete was not called
        self.vim_client.delete_strategy.assert_not_called()

        # Successful promotion to next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_finishing_vim_strategy_failure_get_hosts(self):
        """Test finishing firmware update with communication error to subcloud"""

        # mock the get_host query fails and raises an exception
        self.sysinv_client.get_hosts.side_effect = \
            Exception("HTTP CommunicationError")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the query was actually attempted
        self.sysinv_client.get_hosts.assert_called()

        # verified the query was tried max retries + 1
        self.assertEqual(finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1,
                         self.sysinv_client.get_hosts.call_count)

        # verify the subsequent sysinv command was never attempted
        self.sysinv_client.get_host_device_list.assert_not_called()

        # verify that the state moves to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    @mock.patch.object(BaseState, 'stopped', return_value=True)
    def test_finishing_fw_update_fails_when_strategy_stops(self, _):
        """Test finishing fw update fails when strategy stops before acquiring

        host device
        """

        self.worker.perform_state_action(self.strategy_step)

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_finishing_fw_update_succeeds_with_enabled_host_device(self):
        """Test finishing fw update succeeds with an enabled host device"""

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]
        self.sysinv_client.get_device_images.return_value = [self.fake_device_image]
        self.sysinv_client.get_device_image_states.return_value = [
            self.fake_device_image_state
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_called_once()
        self.sysinv_client.get_device_image_states.assert_called_once()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_finishing_fw_update_succeeds_with_host_device_disabled(self):
        """Test finishing fw update succeeds with a device disabled"""
        self.fake_device.enabled = False

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_not_called()
        self.sysinv_client.get_device_image_states.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch.object(BaseState, 'stopped')
    def test_finishing_fw_update_fails_when_strategy_stops_with_enabled_host_device(
        self, mock_base_state
    ):
        """Test finishing fw update fails when strategy stops after acquiring

        host device
        """

        mock_base_state.side_effect = [False, True]

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_not_called()
        self.sysinv_client.get_device_image_states.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_finishing_fw_update_fails_with_get_device_image_states_exception(self):
        """Test finishing fw update fails when get_device_image_states raises

        an Exception
        """

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]
        self.sysinv_client.get_device_images.return_value = [self.fake_device_image]
        self.sysinv_client.get_device_image_states.side_effect = Exception()

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.assertEqual(
            self.sysinv_client.get_device_images.call_count,
            finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1
        )
        # TODO(rlima): update the code to fix the error where the call_count is
        # always greater than the DEFAULT_MAX_FAILED_QUERIES
        self.assertEqual(
            self.sysinv_client.get_device_image_states.call_count,
            finishing_fw_update.DEFAULT_MAX_FAILED_QUERIES + 1
        )

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_finishing_fw_update_fails_with_pending_image_state(self):
        """Test finishing fw update fails with pending image state

        In this scenarion, there are three failed image states in order to cover all
        possible outcomes in their validation:
        - The first is complete with the status pending
        - The second has the same status but its image is None
        - The third has the same status but rs device is None
        """

        self.fake_device_image_state.status = 'pending'

        fake_device_image_state_with_image_none = \
            self._create_fake_device_image_state(
                self.fake_device.uuid, None, 'pending'
            )
        fake_device_image_state_with_device_none = \
            self._create_fake_device_image_state(
                None, self.fake_device_image.uuid, 'pending'
            )

        self.sysinv_client.get_hosts.return_value = [self.fake_host]
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]
        self.sysinv_client.get_device_images.return_value = [self.fake_device_image]
        self.sysinv_client.get_device_image_states.return_value = [
            self.fake_device_image_state,
            fake_device_image_state_with_image_none,
            fake_device_image_state_with_device_none
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_hosts.assert_called_once()
        self.sysinv_client.get_host_device_list.assert_called_once()
        self.sysinv_client.get_device_images.assert_called_once()
        self.sysinv_client.get_device_image_states.assert_called_once()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )
