#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
import uuid

from dcmanager.common import consts

from dcmanager.tests.unit.manager.states.fakes import FakeDeviceImage
from dcmanager.tests.unit.manager.states.firmware.test_base \
    import TestFwUpdateState

VENDOR_1 = '1001'
VENDOR_2 = '2002'
VENDOR_3 = '3003'
# These devices must have different pci vendor or device to be unique
FAKE_DEVICE_1 = FakeDeviceImage(str(uuid.uuid4()),
                                pci_vendor=VENDOR_1,
                                applied=True)
FAKE_DEVICE_2 = FakeDeviceImage(str(uuid.uuid4()),
                                pci_vendor=VENDOR_2,
                                applied=True)
FAKE_DEVICE_3 = FakeDeviceImage(str(uuid.uuid4()),
                                pci_vendor=VENDOR_3,
                                applied=True)

EMPTY_DEVICE_IMAGES = []
THREE_DEVICE_IMAGES = [FAKE_DEVICE_1, FAKE_DEVICE_2, FAKE_DEVICE_3, ]


class TestFwUpdateImportingFirmwareStage(TestFwUpdateState):

    def setUp(self):
        self.skipTest("Importing Firmware under construction")
        super(TestFwUpdateImportingFirmwareStage, self).setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = \
            consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_IMPORTING_FIRMWARE)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.sysinv_client.get_device_images = mock.MagicMock()
        self.sysinv_client.get_device_image = mock.MagicMock()
        self.sysinv_client.get_device_image_states = mock.MagicMock()
        self.sysinv_client.remove_device_image = mock.MagicMock()
        self.sysinv_client.upload_device_image = mock.MagicMock()

    def test_importing_firmware_empty_system_controller(self):
        """Test importing firmware step when system controller has no FW"""

        # first query is system controller
        # second query is subcloud
        self.sysinv_client.get_device_images.side_effect = [
            EMPTY_DEVICE_IMAGES,
            THREE_DEVICE_IMAGES, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # 0 on system controller, 3 on subcloud means
        # - 0 calls to import
        self.sysinv_client.upload_device_image.assert_not_called()
        # - 0 calls to apply
        # - 3 calls to remove
        self.assertEqual(3, self.sysinv_client.remove_device_image.call_count)

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_importing_firmware_empty_subcloud(self):
        """Test importing firmware step when subcloud has no FW"""

        # first query is system controller
        # second query is subcloud
        self.sysinv_client.get_device_images.side_effect = [
            THREE_DEVICE_IMAGES,
            EMPTY_DEVICE_IMAGES, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # 3 on system controller, 0 on subcloud means
        # - 3 calls to import
        self.assertEqual(3, self.sysinv_client.upload_device_image.call_count)
        # - 0 calls to apply
        # - 0 calls to remove
        self.sysinv_client.remove_device_image.assert_not_called()

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_importing_firmware_skips(self):
        """Test importing firmware skips when subcloud matches controller."""

        # first query is system controller
        # second query is subcloud
        # Both are the same
        self.sysinv_client.get_device_images.side_effect = [
            THREE_DEVICE_IMAGES,
            THREE_DEVICE_IMAGES, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # There should be no calls to upload or remove
        self.sysinv_client.remove_device_image.assert_not_called()
        self.sysinv_client.upload_device_image.assert_not_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
