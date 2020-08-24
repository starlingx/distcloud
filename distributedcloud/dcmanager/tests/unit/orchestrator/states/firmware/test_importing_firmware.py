#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
import uuid

from dcmanager.common import consts

from dcmanager.tests.unit.orchestrator.states.fakes import FakeController
from dcmanager.tests.unit.orchestrator.states.fakes import FakeDevice
from dcmanager.tests.unit.orchestrator.states.fakes import FakeDeviceImage
from dcmanager.tests.unit.orchestrator.states.fakes import FakeDeviceLabel
from dcmanager.tests.unit.orchestrator.states.firmware.test_base \
    import TestFwUpdateState

VENDOR_1 = '1001'
VENDOR_2 = '2002'
VENDOR_3 = '3003'

VENDOR_DEVICE_1 = '9009'

FAKE_SUBCLOUD_CONTROLLER = FakeController()
FAKE_SUBCLOUD_DEVICE = FakeDevice(str(uuid.uuid4()),
                                  pvendor_id=VENDOR_1,
                                  pdevice_id=VENDOR_DEVICE_1)
FAKE_SUBCLOUD_LABEL = FakeDeviceLabel(label_key='abc',
                                      label_value='123',
                                      pcidevice_uuid=FAKE_SUBCLOUD_DEVICE.uuid)
FAKE_ALL_LABEL = [{}, ]
# These three enabled images are for three different devices
FAKE_IMAGE_1 = FakeDeviceImage(str(uuid.uuid4()),
                               pci_vendor=VENDOR_1,
                               pci_device=VENDOR_DEVICE_1,
                               applied=True,
                               applied_labels=FAKE_ALL_LABEL)
FAKE_IMAGE_2 = FakeDeviceImage(str(uuid.uuid4()),
                               pci_vendor=VENDOR_2,
                               applied=True,
                               applied_labels=FAKE_ALL_LABEL)
FAKE_IMAGE_3 = FakeDeviceImage(str(uuid.uuid4()),
                               pci_vendor=VENDOR_3,
                               applied=True,
                               applied_labels=FAKE_ALL_LABEL)


EMPTY_DEVICE_IMAGES = []
THREE_DEVICE_IMAGES = [FAKE_IMAGE_1, FAKE_IMAGE_2, FAKE_IMAGE_3, ]


class TestFwUpdateImportingFirmwareStage(TestFwUpdateState):

    def setUp(self):
        super(TestFwUpdateImportingFirmwareStage, self).setUp()

        # set the next state in the chain (when this state is successful)
        self.on_success_state = \
            consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_IMPORTING_FIRMWARE)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.sysinv_client.get_device_images = mock.MagicMock()
        self.sysinv_client.get_device_image_states = mock.MagicMock()
        self.sysinv_client.apply_device_image = mock.MagicMock()
        self.sysinv_client.remove_device_image = mock.MagicMock()
        self.sysinv_client.upload_device_image = mock.MagicMock()
        # get_hosts is only called on subcloud
        self.sysinv_client.get_hosts = mock.MagicMock()
        self.sysinv_client.get_hosts.return_value = \
            [FAKE_SUBCLOUD_CONTROLLER, ]
        # get_host_device_list is only called on subcloud
        self.sysinv_client.get_host_device_list = mock.MagicMock()
        self.sysinv_client.get_host_device_list.return_value = \
            [FAKE_SUBCLOUD_DEVICE, ]
        # the labels for the device on the subcloud
        self.sysinv_client.get_device_label_list = mock.MagicMock()
        self.sysinv_client.get_device_label_list.return_value = \
            [FAKE_SUBCLOUD_LABEL, ]

    def test_importing_firmware_empty_system_controller(self):
        """Test importing firmware step when system controller has no FW"""

        # first query is system controller
        # second query is subcloud
        self.sysinv_client.get_device_images.side_effect = [
            EMPTY_DEVICE_IMAGES,
            THREE_DEVICE_IMAGES, ]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Any applied images on subcloud should be removed
        self.assertEqual(3, self.sysinv_client.remove_device_image.call_count)

        # 0 on system controller so there should be no calls to upload
        self.sysinv_client.upload_device_image.assert_not_called()

        # Since no active images on system controller, apply will not be called
        self.sysinv_client.apply_device_image.assert_not_called()

        # Successful promotion to next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch('os.path.isfile')
    def test_importing_firmware_empty_subcloud(self, mock_isfile):
        """Test importing firmware step when subcloud has no FW"""

        mock_isfile.return_value = True
        # first query is system controller
        # second query is subcloud
        self.sysinv_client.get_device_images.side_effect = [
            THREE_DEVICE_IMAGES,
            EMPTY_DEVICE_IMAGES, ]

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
