#
# Copyright (c) 2020-2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.firmware.test_base \
    import TestFwUpdateState

VENDOR_1 = "1001"
VENDOR_2 = "2002"
VENDOR_3 = "3003"

VENDOR_DEVICE_1 = '9009'
VENDOR_DEVICE_2 = '9009'
VENDOR_DEVICE_3 = '9009'

FAKE_SUBCLOUD_CONTROLLER = FakeController()
FAKE_ALL_LABEL = [{}]


class TestFwUpdateImportingFirmwareStage(TestFwUpdateState):

    def setUp(self):
        super(TestFwUpdateImportingFirmwareStage, self).setUp()

        # Sets up the necessary variables for mocking
        self.fake_device = self._create_fake_device(VENDOR_1, VENDOR_DEVICE_1)
        fake_device_label = self._create_fake_device_label(
            'fake key', 'fake label', self.fake_device.uuid
        )
        fake_device_image_from_vendor_1 = self._create_fake_device_image(
            VENDOR_1, VENDOR_DEVICE_1, True, FAKE_ALL_LABEL
        )
        fake_device_image_from_vendor_2 = self._create_fake_device_image(
            VENDOR_2, VENDOR_DEVICE_2, True, FAKE_ALL_LABEL
        )
        fake_device_image_from_vendor_3 = self._create_fake_device_image(
            VENDOR_3, VENDOR_DEVICE_3, True, FAKE_ALL_LABEL
        )
        self.fake_device_image_list = [
            fake_device_image_from_vendor_1,
            fake_device_image_from_vendor_2,
            fake_device_image_from_vendor_3
        ]
        self.empty_fake_device_image_list = []

        self.fake_device_image = self._create_fake_device_image_state(
            self.fake_device.uuid,
            fake_device_image_from_vendor_1.uuid,
            'completed'
        )

        # set the next state in the chain (when this state is successful)
        self.on_success_state = consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_IMPORTING_FIRMWARE
        )

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.sysinv_client.get_device_images = mock.MagicMock()
        self.sysinv_client.get_device_image_states = mock.MagicMock()
        self.sysinv_client.apply_device_image = mock.MagicMock()
        self.sysinv_client.remove_device_image = mock.MagicMock()
        self.sysinv_client.upload_device_image = mock.MagicMock()

        # get_hosts is only called on subcloud
        self.sysinv_client.get_hosts = mock.MagicMock()
        self.sysinv_client.get_hosts.return_value = [FAKE_SUBCLOUD_CONTROLLER]

        # get_host_device_list is only called on subcloud
        self.sysinv_client.get_host_device_list = mock.MagicMock()
        self.sysinv_client.get_host_device_list.return_value = [self.fake_device]

        # the labels for the device on the subcloud
        self.sysinv_client.get_device_label_list = mock.MagicMock()
        self.sysinv_client.get_device_label_list.return_value = [fake_device_label]

    def test_importing_firmware_empty_system_controller(self):
        """Test importing firmware step when system controller has no FW"""

        # first query is system controller
        # second query is subcloud
        self.sysinv_client.get_device_images.side_effect = [
            self.empty_fake_device_image_list, self.fake_device_image_list
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Any applied images on subcloud should be removed
        self.assertEqual(3, self.sysinv_client.remove_device_image.call_count)

        # 0 on system controller so there should be no calls to upload
        self.sysinv_client.upload_device_image.assert_not_called()

        # Since no active images on system controller, apply will not be called
        self.sysinv_client.apply_device_image.assert_not_called()

        # Successful promotion to next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch("os.path.isfile", return_value=True)
    def test_importing_firmware_empty_subcloud(self, _):
        """Test importing firmware step when subcloud has no FW"""

        # first query is system controller
        # second query is subcloud
        self.sysinv_client.get_device_images.side_effect = [
            self.fake_device_image_list, self.empty_fake_device_image_list
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # There are no images applied on subcloud, so no calls to remove
        self.sysinv_client.remove_device_image.assert_not_called()

        # There are no images and only 1 matching device on the subcloud
        # so only one of the three system controller images will be uploaded
        # and applied
        self.assertEqual(1, self.sysinv_client.upload_device_image.call_count)

        # There are no applied images on subcloud, so apply three times
        self.assertEqual(1, self.sysinv_client.apply_device_image.call_count)

        # Successful promotion to next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_importing_firmware_skips(self):
        """Test importing firmware skips when subcloud matches controller."""

        # first query is system controller
        # second query is subcloud
        # Both are the same
        self.sysinv_client.get_device_images.side_effect = [
            self.fake_device_image_list, self.fake_device_image_list
        ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # There should be no calls to upload or remove
        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()

        # On success, should have moved to the next state
        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_importing_firmware_succeeds_without_enabled_host_device_list(self):
        """Test importing firmware succeeds without enabled host device list"""

        self.sysinv_client.get_host_device_list.return_value = [
            self._create_fake_device(VENDOR_2, VENDOR_DEVICE_2, False)
        ]

        self.sysinv_client.get_device_images.side_effect = [
            self.empty_fake_device_image_list, self.fake_device_image_list
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.get_device_image_states.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch('os.path.isfile', return_value=False)
    def test_importing_firmware_fails_when_image_file_is_missing(self, _):
        """Test importing firmware fails when image file is missing

        The os_path_isfile should raise an Exception
        """

        self.sysinv_client.get_device_images.side_effect = [
            self.fake_device_image_list, self.empty_fake_device_image_list
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    @mock.patch('os.path.isfile', return_value=True)
    def test_importing_firmware_succeeds_with_device_image_state_completed(self, _):
        """Test importing firmware success with a device image state completed"""

        self.sysinv_client.get_device_images.side_effect = [
            self.fake_device_image_list, self.empty_fake_device_image_list
        ]

        self.sysinv_client.get_device_image_states.return_value = [
            self.fake_device_image
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_called_once()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch('os.path.isfile', return_value=True)
    def test_importing_firmware_succeeds_with_device_image_state_pending(self, _):
        """Test importing firmware success with a device image state pending"""

        self.sysinv_client.get_device_images.side_effect = [
            self.fake_device_image_list, self.empty_fake_device_image_list
        ]

        self.fake_device_image.status = 'pending'

        self.sysinv_client.get_device_image_states.return_value = [
            self.fake_device_image
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_called_once()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch('os.path.isfile', return_value=True)
    def test_importing_firmware_succeeds_with_applied_subcloud_images(self, _):
        """Test importing firmware success with applied subcloudimages"""

        fake_device_image_with_label = self._create_fake_device_image(
            VENDOR_1, VENDOR_DEVICE_1, True, [{'fake label': 'fake value'}]
        )

        self.fake_device_image_list.append(fake_device_image_with_label)

        self.sysinv_client.get_device_images.side_effect = [
            self.empty_fake_device_image_list,
            self.fake_device_image_list,
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.assertEqual(
            self.sysinv_client.remove_device_image.call_count,
            len(self.fake_device_image_list,)
        )
        self.sysinv_client.apply_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    @mock.patch('os.path.isfile', return_value=True)
    def test_importing_firmware_succeeds_without_subcloud_device_image_states(
        self, _
    ):
        """Test importing firmware success without subcloud device image states

        In this scenario, a device image with applied_labels should have them
        applied to the device image
        """

        fake_device_image_with_label = self._create_fake_device_image(
            VENDOR_1, VENDOR_DEVICE_1, True, [{'fake key': 'fake label'}]
        )

        self.sysinv_client.get_device_images.side_effect = [
            [fake_device_image_with_label],
            self.empty_fake_device_image_list
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_called_once()
        self.sysinv_client.upload_device_image.assert_called_once()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_importing_firmware_succeeds_with_device_image_without_label(self):
        """Test importing firmware succeeds with device image without label

        There are two different validations being done in this test case:
        - Using a device image without applied labels
        - Returning an empty device_label_list
        Both conditions are validated in firmware/utils.py and result in the
        device being None
        """

        fake_device_image_with_label = self._create_fake_device_image(
            VENDOR_1, VENDOR_DEVICE_1, True, None
        )
        self.sysinv_client.get_device_label_list.return_value = []

        self.sysinv_client.get_device_images.side_effect = [
            [fake_device_image_with_label],
            self.empty_fake_device_image_list
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_importing_firmware_succeeds_with_device_inelegible(self):
        """Test importing firmware succeeds with device image inalegible

        When the device image is inelegible, the check_subcloud_device_has_image
        method from utils returns None, exiting the execution successfully
        """

        fake_device_image_with_label = self._create_fake_device_image(
            VENDOR_1, VENDOR_DEVICE_1, True, [{'fake label': 'fake value'}]
        )

        self.sysinv_client.get_device_images.side_effect = [
            [fake_device_image_with_label],
            self.empty_fake_device_image_list
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )

    def test_importing_firmware_succeeds_with_device_not_applied(self):
        """Test importing firmware succeeds with device not applied"""

        fake_device_image_with_label = self._create_fake_device_image(
            VENDOR_1, VENDOR_DEVICE_1, False, None
        )
        self.sysinv_client.get_device_images.side_effect = [
            [fake_device_image_with_label],
            self.empty_fake_device_image_list
        ]

        self.worker.perform_state_action(self.strategy_step)

        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()
        self.sysinv_client.apply_device_image.assert_not_called()

        self.assert_step_updated(
            self.strategy_step.subcloud_id, self.on_success_state
        )
