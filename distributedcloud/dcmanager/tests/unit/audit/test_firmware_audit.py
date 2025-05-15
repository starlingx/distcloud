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

import mock

from dccommon import consts as dccommon_consts
from dccommon.endpoint_cache import EndpointCache
from dcmanager.audit import firmware_audit
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class PCIDevice(object):
    def __init__(self, uuid, name, pciaddr, pvendor_id, pdevice_id, enabled):
        self.uuid = uuid
        self.name = name
        self.pciaddr = pciaddr
        self.pvendor_id = pvendor_id
        self.pdevice_id = pdevice_id
        self.enabled = enabled


class DeviceImage(object):
    def __init__(
        self,
        uuid,
        bitstream_type,
        bitstream_id,
        bmc,
        retimer_included,
        key_signature,
        revoke_key_id,
        applied,
        pci_vendor,
        pci_device,
        applied_labels,
    ):
        self.uuid = uuid
        self.bitstream_type = bitstream_type
        self.bitstream_id = bitstream_id
        self.bmc = bmc
        self.retimer_included = retimer_included
        self.key_signature = key_signature
        self.revoke_key_id = revoke_key_id
        self.applied = applied
        self.pci_vendor = pci_vendor
        self.pci_device = pci_device
        self.applied_labels = applied_labels


class DeviceImageState(object):
    def __init__(self, pcidevice_uuid, image_uuid, status):
        self.pcidevice_uuid = pcidevice_uuid
        self.image_uuid = image_uuid
        self.status = status


class Host(object):
    def __init__(self, uuid, name):
        self.uuid = uuid
        self.name = name


class DeviceLabels(object):
    def __init__(self, pcidevice_uuid, label_key, label_value):
        self.pcidevice_uuid = pcidevice_uuid
        self.label_key = label_key
        self.label_value = label_value


HOST1 = Host("04ae0e01-13b6-4105", "controller-0")
# Device not enabled
PCI_DEVICE1 = PCIDevice(
    "06789e01-13b6-2345", "pci_0000_00_01_0", "0000:00:02.0", "1111", "2222", False
)
# Device not enabled
PCI_DEVICE2 = PCIDevice(
    "06789e01-13b6-2346", "pci_0000_00_02_0", "0000:00:03.0", "1111", "2222", False
)
# Device enabled
PCI_DEVICE3 = PCIDevice(
    "06789e01-13b6-2347", "pci_0000_00_03_0", "0000:00:04.0", "1111", "2222", True
)
# Device enabled
PCI_DEVICE4 = PCIDevice(
    "06789e01-13b6-2347", "pci_0000_00_03_0", "0000:00:04.0", "1000", "2000", True
)
# Device image has been applied
DEVICE_IMAGE1 = DeviceImage(
    "7e794693-2060-4e9e-b0bd-b281b059e8e4",
    "functional",
    "0x2383a62a010504",
    True,
    True,
    "",
    "",
    True,
    "1111",
    "2222",
    [{}],
)
# Device image has not been applied
DEVICE_IMAGE2 = DeviceImage(
    "09100124-5ae9-44d8-aefc-a192b8f27360",
    "functional",
    "0x2383a62a010504",
    True,
    True,
    "",
    "",
    False,
    "1111",
    "2222",
    [{}],
)
# Device image has been applied
DEVICE_IMAGE3 = DeviceImage(
    "ef4c39b1-81e9-42dd-b850-06fc8833b47c",
    "functional",
    "0x2383a62a010504",
    True,
    True,
    "",
    "",
    True,
    "1111",
    "2222",
    [{"key1": "value1"}],
)
DEVICE_LABEL1 = DeviceLabels("06789e01-13b6-2347", "key1", "value1")
# Device image state where image is written to device
DEVICE_IMAGE_STATE1 = DeviceImageState(
    PCI_DEVICE4.uuid, "04ae0e01-13b6-4105", "completed"
)
# Device image state where image is applied but not written to the device
DEVICE_IMAGE_STATE2 = DeviceImageState(
    PCI_DEVICE4.uuid, "04ae0e01-13b6-4105", "pending"
)


class FakeSysinvClient(object):
    def __init__(
        self,
        region=None,
        session=None,
        endpoint=None,
        device_image=None,
        device_images=[],
        device_image_states=[],
        pci_devices=[],
        hosts=[],
        device_labels=[],
    ):
        self.device_image = device_image
        self.device_images = device_images
        self.device_image_states = device_image_states
        self.pci_devices = pci_devices
        self.hosts = hosts
        self.device_labels = device_labels

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_image(self, device_image_uuid):
        return self.device_image

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class TestFirmwareAudit(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self.mock_regionone_sysinvclient = self._mock_object(
            firmware_audit, "SysinvClient"
        )
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_log = self._mock_object(firmware_audit, "LOG")

        self.mock_regionone_sysinvclient = self._mock_object(
            firmware_audit, "SysinvClient"
        )
        self.mock_subcloud_sysinvclient = mock.MagicMock()

        self.firmware_audit = firmware_audit.FirmwareAudit()
        self.audit_manager = subcloud_audit_manager.SubcloudAuditManager()
        self.audit_manager.firmware_audit = self.firmware_audit

        self.subcloud = create_fake_subcloud(self.ctx)
        self._setup_objects()

    def _setup_objects(self):
        self.fake_sysinv_client = {"no-enabled-devices": None}

    def _rpc_convert(self, object_list):
        # Convert to dict like what would happen calling via RPC
        dict_results = []

        for result in object_list:
            dict_results.append(result.to_dict())

        return dict_results

    def _get_firmware_audit_data(self):
        (firmware_audit_data, _, _, _) = self.audit_manager._get_audit_data(
            True, False, False, False
        )

        if firmware_audit_data is not None:
            # Convert to dict like what would happen calling via RPC
            return self._rpc_convert(firmware_audit_data)
        return None

    def _test_firmware_audit(self, sync_status):
        response = self.firmware_audit.get_subcloud_sync_status(
            self.mock_subcloud_sysinvclient(),
            self._get_firmware_audit_data(),
            self.subcloud.name,
        )

        self.assertEqual(response, sync_status)

    def test_firmware_audit_region_one_client_creation_exception(self):
        self.mock_regionone_sysinvclient.side_effect = Exception("fake")

        response = self._get_firmware_audit_data()

        self.assertIsNone(response)
        self.mock_log.exception.assert_called_with(
            "Failure initializing Sysinv Client, skip firmware audit."
        )

    def test_firmware_audit_empty_regionone_response_on_get_device_images_exception(
        self,
    ):
        self.mock_regionone_sysinvclient().get_device_images.side_effect = Exception()

        response = self._get_firmware_audit_data()

        self.assertEqual(response, [])
        self.mock_log.exception.assert_called_with(
            "Cannot retrieve device images for RegionOne, skip firmware audit"
        )

    def test_firmware_audit_skip_on_get_all_hosts_device_list_exception(self):
        self.mock_subcloud_sysinvclient().get_all_hosts_device_list.side_effect = (
            Exception("fake")
        )

        self._test_firmware_audit(None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Cannot retrieve host device list, skip firmware "
            "audit."
        )

    def test_firmware_audit_skip_on_get_device_image_states_exception(self):
        self.mock_subcloud_sysinvclient().get_all_hosts_device_list.return_value = [
            PCI_DEVICE3,
        ]
        self.mock_subcloud_sysinvclient().get_device_image_states.side_effect = (
            Exception("fake")
        )

        self._test_firmware_audit(None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Cannot retrieve device image states, skip firmware "
            "audit."
        )

    def test_firmware_audit_skip_on_get_device_label_list_exception(self):
        self.mock_subcloud_sysinvclient().get_all_hosts_device_list.return_value = [
            PCI_DEVICE3,
        ]
        self.mock_subcloud_sysinvclient().get_device_label_list.side_effect = Exception(
            "fake"
        )

        self._test_firmware_audit(None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Cannot retrieve device label list, skip firmware "
            "audit."
        )

    def test_firmware_audit_skip_on_get_device_images_exception(self):
        self.mock_subcloud_sysinvclient().get_all_hosts_device_list.return_value = [
            PCI_DEVICE3,
        ]
        self.mock_subcloud_sysinvclient().get_device_images.return_value = []
        self.mock_subcloud_sysinvclient().get_device_images.side_effect = Exception(
            "fake"
        )

        self._test_firmware_audit(None)
        self.mock_log.exception.assert_called_with(
            "Subcloud: subcloud1. Cannot retrieve device images, skip firmware audit."
        )

    def test_firmware_audit_no_enabled_devices_on_subcloud(self):
        self.mock_subcloud_sysinvclient.return_value = FakeSysinvClient(
            device_images=[DEVICE_IMAGE1],
            pci_devices=[PCI_DEVICE1, PCI_DEVICE2],
            hosts=[HOST1],
        )
        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_firmware_audit_apply_image_to_all_devices(self):
        self.mock_subcloud_sysinvclient.return_value = FakeSysinvClient(
            device_images=[DEVICE_IMAGE1],
            device_image=DEVICE_IMAGE1,
            pci_devices=[PCI_DEVICE2, PCI_DEVICE3],
            hosts=[HOST1],
            device_image_states=[DEVICE_IMAGE_STATE1],
            device_labels=[DEVICE_LABEL1],
        )
        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_firmware_audit_image_not_applied(self):
        sysinv_client = FakeSysinvClient(
            device_images=[DEVICE_IMAGE1],
            pci_devices=[PCI_DEVICE2, PCI_DEVICE3],
            hosts=[HOST1],
            # If there is no entry in device image state
            # list, it means that image is not applied
            device_image_states=[],
            device_labels=[DEVICE_LABEL1],
        )
        self.mock_subcloud_sysinvclient.return_value = sysinv_client
        self.mock_regionone_sysinvclient.return_value = sysinv_client

        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_firmware_audit_image_not_written(self):
        sysinv_client = FakeSysinvClient(
            device_images=[DEVICE_IMAGE1, DEVICE_IMAGE2],
            pci_devices=[PCI_DEVICE2, PCI_DEVICE3],
            hosts=[HOST1],
            device_image_states=[DEVICE_IMAGE_STATE2],
            device_labels=[DEVICE_LABEL1],
        )
        self.mock_subcloud_sysinvclient.return_value = sysinv_client
        self.mock_regionone_sysinvclient.return_value = sysinv_client

        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_firmware_audit_image_with_labels(
        self,
    ):
        self.mock_subcloud_sysinvclient.return_value = FakeSysinvClient(
            device_image=DEVICE_IMAGE3,
            device_images=[DEVICE_IMAGE3],
            pci_devices=[PCI_DEVICE2, PCI_DEVICE3],
            hosts=[HOST1],
            device_image_states=[DEVICE_IMAGE_STATE1],
            device_labels=[DEVICE_LABEL1],
        )
        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_firmware_audit_no_matching_label_for_device_on_subcloud(self):
        self.mock_subcloud_sysinvclient.return_value = FakeSysinvClient(
            device_images=[DEVICE_IMAGE3],
            pci_devices=[PCI_DEVICE2, PCI_DEVICE3],
            hosts=[HOST1],
            device_image_states=[DEVICE_IMAGE_STATE1],
            # No matching device label
            device_labels=[],
        )
        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_IN_SYNC)

    def test_firmware_audit_no_matching_device_id_on_subcloud(self):
        self.mock_subcloud_sysinvclient.return_value = FakeSysinvClient(
            device_images=[DEVICE_IMAGE3],
            pci_devices=[PCI_DEVICE4],
            hosts=[HOST1],
            device_image_states=[DEVICE_IMAGE_STATE1],
            device_labels=[DEVICE_LABEL1],
        )
        self._test_firmware_audit(dccommon_consts.SYNC_STATUS_IN_SYNC)
