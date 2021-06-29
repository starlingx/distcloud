# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

from oslo_config import cfg

import sys
sys.modules['fm_core'] = mock.Mock()

from dcmanager.audit import firmware_audit
from dcmanager.audit import patch_audit
from dcmanager.audit import subcloud_audit_manager
from dcmanager.common import consts
from dcmanager.tests import base
from dcmanager.tests import utils

from dcorch.common import consts as dcorch_consts


CONF = cfg.CONF


class FakeDCManagerAPI(object):

    def __init__(self):
        self.update_subcloud_availability = mock.MagicMock()
        self.update_subcloud_endpoint_status = mock.MagicMock()


class FakeAuditWorkerAPI(object):

    def __init__(self):
        self.audit_subclouds = mock.MagicMock()


class PCIDevice(object):
    def __init__(self, uuid, name,
                 pciaddr, pvendor_id,
                 pdevice_id, enabled):
        self.uuid = uuid
        self.name = name
        self.pciaddr = pciaddr
        self.pvendor_id = pvendor_id
        self.pdevice_id = pdevice_id
        self.enabled = enabled


class DeviceImage(object):
    def __init__(self, uuid, applied, pci_vendor,
                 pci_device, applied_labels):
        self.uuid = uuid
        self.applied = applied
        self.pci_vendor = pci_vendor
        self.pci_device = pci_device
        self.applied_labels = applied_labels


class DeviceImageState(object):
    def __init__(self, pcidevice_uuid, image_uuid,
                 status):
        self.pcidevice_uuid = pcidevice_uuid
        self.image_uuid = image_uuid
        self.status = status


class Host(object):
    def __init__(self, uuid, name):
        self.uuid = uuid
        self.name = name


class DeviceLabels(object):
    def __init__(self, pcidevice_uuid,
                 label_key, label_value):
        self.pcidevice_uuid = pcidevice_uuid
        self.label_key = label_key
        self.label_value = label_value


HOST1 = Host('04ae0e01-13b6-4105',
             'controller-0')

# Device not enabled
PCI_DEVICE1 = PCIDevice('06789e01-13b6-2345',
                        'pci_0000_00_01_0',
                        '0000:00:02.0',
                        '1111',
                        '2222',
                        False)

# Device not enabled
PCI_DEVICE2 = PCIDevice('06789e01-13b6-2346',
                        'pci_0000_00_02_0',
                        '0000:00:03.0',
                        '1111',
                        '2222',
                        False)

# Device enabled
PCI_DEVICE3 = PCIDevice('06789e01-13b6-2347',
                        'pci_0000_00_03_0',
                        '0000:00:04.0',
                        '1111',
                        '2222',
                        True)

# Device enabled
PCI_DEVICE4 = PCIDevice('06789e01-13b6-2347',
                        'pci_0000_00_03_0',
                        '0000:00:04.0',
                        '1000',
                        '2000',
                        True)

# Device image has been applied
DEVICE_IMAGE1 = DeviceImage('04ae0e01-13b6-4105',
                            True,
                            '1111',
                            '2222',
                            [{}])

# Device image has not been applied
DEVICE_IMAGE2 = DeviceImage('04ae0e01-13b6-4106',
                            False,
                            '1111',
                            '2222',
                            [{}])

# Device image has been applied
DEVICE_IMAGE3 = DeviceImage('04ae0e01-13b6-4105',
                            True,
                            '1111',
                            '2222',
                            [{"key1": "value1"}])

DEVICE_LABEL1 = DeviceLabels('06789e01-13b6-2347',
                             'key1',
                             'value1')

# Device image state where image is written to device
DEVICE_IMAGE_STATE1 = DeviceImageState(PCI_DEVICE4.uuid,
                                       '04ae0e01-13b6-4105',
                                       'completed')

# Device image state where image is applied but not written
# to the device
DEVICE_IMAGE_STATE2 = DeviceImageState(PCI_DEVICE4.uuid,
                                       '04ae0e01-13b6-4105',
                                       'pending')


class FakeKeystoneClient(object):
    def __init__(self):
        self.keystone_client = mock.MagicMock()
        self.session = mock.MagicMock()
        self.endpoint_cache = mock.MagicMock()


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

    def get_device_images(self):
        return self.device_images


class FakeSysinvClientImageWithoutLabels(object):
    def __init__(self, region, session, endpoint):
        self.region = region
        self.session = session
        self.endpoint = endpoint
        self.device_images = [DEVICE_IMAGE1]
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE1]
        self.device_labels = [DEVICE_LABEL1]

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class FakeSysinvClientImageNotApplied(object):
    def __init__(self, region, session, endpoint):
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

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class FakeSysinvClientImageNotWritten(object):
    def __init__(self, region, session, endpoint):
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
        self.device_images = [DEVICE_IMAGE3]
        self.pci_devices = [PCI_DEVICE2, PCI_DEVICE3]
        self.hosts = [HOST1]
        self.device_image_states = [DEVICE_IMAGE_STATE1]
        self.device_labels = [DEVICE_LABEL1]

    def get_hosts(self):
        return self.hosts

    def get_host_device_list(self, host_name):
        return self.pci_devices

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

    def get_device_images(self):
        return self.device_images

    def get_device_image_states(self):
        return self.device_image_states

    def get_device_label_list(self):
        return self.device_labels


class TestFirmwareAudit(base.DCManagerTestCase):
    def setUp(self):
        super(TestFirmwareAudit, self).setUp()
        self.ctxt = utils.dummy_context()

        # Mock the DCManager API
        self.fake_dcmanager_api = FakeDCManagerAPI()
        p = mock.patch('dcmanager.rpc.client.ManagerClient')
        self.mock_dcmanager_api = p.start()
        self.mock_dcmanager_api.return_value = self.fake_dcmanager_api
        self.addCleanup(p.stop)

        # Mock the Audit Worker API
        self.fake_audit_worker_api = FakeAuditWorkerAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditWorkerClient')
        self.mock_audit_worker_api = p.start()
        self.mock_audit_worker_api.return_value = self.fake_audit_worker_api
        self.addCleanup(p.stop)

    def _rpc_convert(self, object_list):
        # Convert to dict like what would happen calling via RPC
        dict_results = []
        for result in object_list:
            dict_results.append(result.to_dict())
        return dict_results

    def get_fw_audit_data(self, am):
        patch_audit_data, firmware_audit_data, kubernetes_audit_data, kube_root = \
            am._get_audit_data(True, True, True, True)

        # Convert to dict like what would happen calling via RPC
        firmware_audit_data = self._rpc_convert(firmware_audit_data)
        return firmware_audit_data

    def test_init(self):
        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        self.assertIsNotNone(fm)
        self.assertEqual(self.ctxt, fm.context)
        self.assertEqual(self.fake_dcmanager_api, fm.dcmanager_rpc_client)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_firmware_audit_data_to_sync(self, mock_context,
                                            mock_fw_openstack_driver,
                                            mock_fw_sysinv_client,
                                            mock_openstack_driver,
                                            mock_patching_client,
                                            mock_sysinv_client):

        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoAuditData

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_enabled_devices_on_subcloud(self, mock_context,
                                            mock_fw_openstack_driver,
                                            mock_fw_sysinv_client,
                                            mock_openstack_driver,
                                            mock_patching_client,
                                            mock_sysinv_client):

        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoEnabledDevices

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_apply_image_to_all_devices(self, mock_context,
                                        mock_fw_openstack_driver,
                                        mock_fw_sysinv_client,
                                        mock_openstack_driver,
                                        mock_patching_client,
                                        mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageWithoutLabels

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_image_not_applied(self, mock_context,
                               mock_fw_openstack_driver,
                               mock_fw_sysinv_client,
                               mock_openstack_driver,
                               mock_patching_client,
                               mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageNotApplied

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_image_not_written(self, mock_context,
                               mock_fw_openstack_driver,
                               mock_fw_sysinv_client,
                               mock_openstack_driver,
                               mock_patching_client,
                               mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageNotWritten

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_OUT_OF_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_image_with_labels(self, mock_context,
                               mock_fw_openstack_driver,
                               mock_fw_sysinv_client,
                               mock_openstack_driver,
                               mock_patching_client,
                               mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientImageWithLabels

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_matching_label_for_device_on_subcloud(self, mock_context,
                                                      mock_fw_openstack_driver,
                                                      mock_fw_sysinv_client,
                                                      mock_openstack_driver,
                                                      mock_patching_client,
                                                      mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoMatchingDeviceLabel

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)

    @mock.patch.object(patch_audit, 'SysinvClient')
    @mock.patch.object(patch_audit, 'PatchingClient')
    @mock.patch.object(patch_audit, 'OpenStackDriver')
    @mock.patch.object(firmware_audit, 'SysinvClient')
    @mock.patch.object(firmware_audit, 'OpenStackDriver')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_no_matching_device_id_on_subcloud(self, mock_context,
                                               mock_fw_openstack_driver,
                                               mock_fw_sysinv_client,
                                               mock_openstack_driver,
                                               mock_patching_client,
                                               mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_fw_sysinv_client.side_effect = FakeSysinvClientNoMatchingDeviceId

        fm = firmware_audit.FirmwareAudit(self.ctxt,
                                          self.fake_dcmanager_api)
        am = subcloud_audit_manager.SubcloudAuditManager()
        am.firmware_audit = fm
        firmware_audit_data = self.get_fw_audit_data(am)

        for name in ['subcloud1', 'subcloud2']:
            fm.subcloud_firmware_audit(name, firmware_audit_data)
            expected_calls = [
                mock.call(mock.ANY,
                          subcloud_name=name,
                          endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                          sync_status=consts.SYNC_STATUS_IN_SYNC)]
            self.fake_dcmanager_api.update_subcloud_endpoint_status. \
                assert_has_calls(expected_calls)
