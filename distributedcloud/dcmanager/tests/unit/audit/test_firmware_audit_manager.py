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
from dcmanager.audit import firmware_audit
from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.audit import subcloud_audit_worker_manager
from dcmanager.tests import base

CONF = cfg.CONF


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

# Device image state where image is applied but not written
# to the device
DEVICE_IMAGE_STATE2 = DeviceImageState(
    PCI_DEVICE4.uuid, "04ae0e01-13b6-4105", "pending"
)


class FakeSysinvClientNoEnabledDevices(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE1]
        self.pci_devices = [PCI_DEVICE1, PCI_DEVICE2]
        self.hosts = [HOST1]

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images


class FakeSysinvClientNoAuditData(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE2]
        self.pci_devices = [PCI_DEVICE1, PCI_DEVICE2]

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images


class FakeSysinvClientImageWithoutLabels(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE1]
        self.device_image = DEVICE_IMAGE1
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE1]
        self.device_labels = [DEVICE_LABEL1]

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


class FakeSysinvClientImageNotApplied(object):
    def __init__(self, region=None, session=None, endpoint=None):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE1]
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        # If there is no entry in device image state
        # list, it means that image is not applied
        self.device_image_states = []
        self.device_labels = [DEVICE_LABEL1]

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class FakeSysinvClientImageNotWritten(object):
    def __init__(self, region=None, session=None, endpoint=None):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE1]
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE2]
        self.device_labels = [DEVICE_LABEL1]

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class FakeSysinvClientImageWithLabels(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_image = DEVICE_IMAGE3
        self.device_images = [DEVICE_IMAGE3]
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE1]
        self.device_labels = [DEVICE_LABEL1]

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


class FakeSysinvClientNoMatchingDeviceLabel(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE3]
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE1]
        # No matching device label
        self.device_labels = []

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class FakeSysinvClientNoMatchingDeviceId(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE3]
        self.pci_devices = [PCI_DEVICE4]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE1]
        self.device_labels = [DEVICE_LABEL1]

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_all_hosts_device_list(self):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class TestFirmwareAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_rpc_api_manager_audit_worker_client()
        self._mock_sysinv_client(subcloud_audit_worker_manager)
        self._mock_subcloud_audit_manager_context()
        self.mock_subcloud_audit_manager_context.get_admin_context.return_value = (
            self.ctx
        )

        self.fm = firmware_audit.FirmwareAudit()
        self.am = subcloud_audit_manager.SubcloudAuditManager()
        self.am.firmware_audit = self.fm

    def _rpc_convert(self, object_list):
        # Convert to dict like what would happen calling via RPC
        dict_results = []
        for result in object_list:
            dict_results.append(result.to_dict())
        return dict_results

    def get_fw_audit_data(self):
        (_, firmware_audit_data, _, _, _) = self.am._get_audit_data(
            True, True, True, True, True
        )

        # Convert to dict like what would happen calling via RPC
        firmware_audit_data = self._rpc_convert(firmware_audit_data)
        return firmware_audit_data

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_no_firmware_audit_data_to_sync(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):

        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoAuditData
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_no_enabled_devices_on_subcloud(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):

        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoEnabledDevices
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_apply_image_to_all_devices(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageWithoutLabels
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_image_not_applied(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageNotApplied
        self.mock_sysinv_client.side_effect = FakeSysinvClientImageNotApplied
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_image_not_written(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageNotWritten
        self.mock_sysinv_client.side_effect = FakeSysinvClientImageNotWritten
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_image_with_labels(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageWithLabels
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_no_matching_label_for_device_on_subcloud(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):
        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoMatchingDeviceLabel
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)

    @mock.patch.object(patch_audit, "SysinvClient")
    @mock.patch.object(patch_audit, "PatchingClient")
    @mock.patch.object(patch_audit, "OpenStackDriver")
    @mock.patch.object(firmware_audit, "SysinvClient")
    @mock.patch.object(firmware_audit, "OpenStackDriver")
    def test_no_matching_device_id_on_subcloud(
        self,
        mock_fw_openstack_driver,
        mock_fw_sysinv_client,
        mock_openstack_driver,
        mock_patching_client,
        mock_sysinv_client,
    ):
        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoMatchingDeviceId
        firmware_audit_data = self.get_fw_audit_data()

        subclouds = {
            base.SUBCLOUD_1["name"]: base.SUBCLOUD_1["region_name"],
            base.SUBCLOUD_2["name"]: base.SUBCLOUD_2["region_name"],
        }
        for name, region in subclouds.items():
            response = self.fm.subcloud_firmware_audit(
                self.mock_sysinv_client(), name, firmware_audit_data
            )

            self.assertEqual(response, dccommon_consts.SYNC_STATUS_IN_SYNC)
