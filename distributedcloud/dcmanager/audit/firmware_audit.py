# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

from dcorch.common import consts as dcorch_consts

from dcmanager.common import consts


LOG = logging.getLogger(__name__)


class FirmwareAuditData(object):
    def __init__(self, bitstream_type, bitstream_id,
                 bmc, retimer_included,
                 key_signature, revoke_key_id,
                 applied, pci_vendor,
                 pci_device, applied_labels):
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

    def to_dict(self):
        return {
            'bitstream_type': self.bitstream_type,
            'bitstream_id': self.bitstream_id,
            'bmc': self.bmc,
            'retimer_included': self.retimer_included,
            'key_signature': self.key_signature,
            'revoke_key_id': self.revoke_key_id,
            'applied': self.applied,
            'pci_vendor': self.pci_vendor,
            'pci_device': self.pci_device,
            'applied_labels': self.applied_labels,
        }

    @classmethod
    def from_dict(cls, values):
        if values is None:
            return None
        return cls(**values)


class FirmwareAudit(object):
    """Manages tasks related to firmware audits."""

    def __init__(self, context, dcmanager_state_rpc_client):
        LOG.debug('FirmwareAudit initialization...')
        self.context = context
        self.state_rpc_client = dcmanager_state_rpc_client
        self.audit_count = 0

    def _update_subcloud_sync_status(self, sc_name, sc_endpoint_type,
                                     sc_status):
        self.state_rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=sc_name,
            endpoint_type=sc_endpoint_type,
            sync_status=sc_status)

    def get_regionone_audit_data(self):
        """Query RegionOne to determine what device images have to be applied

        to the system

        :return: A list of device images applied on the system controller

        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_name=consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            endpoint = m_os_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(
                consts.DEFAULT_REGION_NAME, m_os_ks_client.session,
                endpoint=endpoint)
        except Exception:
            LOG.exception('Failure initializing OS Client, skip firmware audit.')
            return None

        filtered_images = []
        try:
            # get_device_images is a list of DeviceImage objects
            local_device_images = sysinv_client.get_device_images()

            # Filter images which have been applied on RegionOne
            for image in local_device_images:
                if image.applied:
                    filtered_images.append(FirmwareAuditData(image.bitstream_type,
                                                             image.bitstream_id,
                                                             image.bmc,
                                                             image.retimer_included,
                                                             image.key_signature,
                                                             image.revoke_key_id,
                                                             image.applied,
                                                             image.pci_vendor,
                                                             image.pci_device,
                                                             image.applied_labels))
            LOG.debug("RegionOne applied_images: %s" % filtered_images)
        except Exception:
            LOG.exception('Cannot retrieve device images for RegionOne, '
                          'skip firmware audit')
        return filtered_images

    def _check_for_label_match(self, subcloud_host_device_label_list,
                               device_uuid,
                               label_key, label_value):
        for device_label in subcloud_host_device_label_list:
            if device_label.pcidevice_uuid and \
                device_uuid == device_label.pcidevice_uuid and \
                label_key == device_label.label_key and \
                label_value == device_label.label_value:
                return True
        return False

    def _check_image_match(self,
                           subcloud_image,
                           system_controller_image):
        if ((system_controller_image.bitstream_type == consts.BITSTREAM_TYPE_ROOT_KEY and
             system_controller_image.root_key == subcloud_image.root_key) or
            (system_controller_image.bitstream_type == consts.BITSTREAM_TYPE_FUNCTIONAL and
             system_controller_image.bitstream_id == subcloud_image.bitstream_id and
             system_controller_image.bmc == subcloud_image.bmc and
             system_controller_image.retimer_included == subcloud_image.retimer_included) or
            (system_controller_image.bitstream_type == consts.BITSTREAM_TYPE_KEY_REVOCATION and
             system_controller_image.revoked_key_ids == subcloud_image.revoked_key_ids)):
                return True
        return False

    def _check_subcloud_device_has_image(self,
                                         subcloud_name,
                                         subcloud_sysinv_client,
                                         image,
                                         enabled_host_device_list,
                                         subcloud_device_image_states,
                                         subcloud_device_label_list):
        apply_to_all_devices = False
        if image.applied_labels:
            # Returns true if the list contains at least one empty dict.
            # An empty dict signifies that image is to be applied to
            # all devices that match the pci vendor and pci device ID.
            apply_to_all_devices = any(not image for image in image.applied_labels)

        for device in enabled_host_device_list:
            if not apply_to_all_devices:
                # If image has to be applied to devices with a matching label
                # and the device label list is empty on the subcloud, report
                # as in-sync
                if not subcloud_device_label_list:
                    break

                # Device is considered eligible if device labels
                # match at least one of the image labels
                is_device_eligible = False
                for image_label in image.applied_labels:
                    label_key = list(image_label.keys())[0]
                    label_value = image_label.get(label_key)
                    is_device_eligible = \
                        self._check_for_label_match(
                            subcloud_device_label_list,
                            device.uuid,
                            label_key,
                            label_value)
                    # If device label matches any image label stop checking
                    # for any other label matches
                    if is_device_eligible:
                        break

                # If this device is not eligible, go to the next device
                if not is_device_eligible:
                    continue

            if image.pci_vendor == device.pvendor_id and \
                image.pci_device == device.pdevice_id:
                device_image_state = None
                subcloud_image = None
                for device_image_state_obj in subcloud_device_image_states:
                    if device_image_state_obj.pcidevice_uuid == device.uuid:
                        try:
                            subcloud_image = subcloud_sysinv_client.\
                                get_device_image(device_image_state_obj.image_uuid)
                        except Exception:
                            LOG.exception('Cannot retrieve device image for '
                                          'subcloud: %s, skip firmware '
                                          'audit' % subcloud_name)
                            return False

                        if self._check_image_match(subcloud_image, image):
                            device_image_state = device_image_state_obj
                            break
                else:
                    # If no device image state is present in the list that
                    # means the image hasn't been applied yet
                    return False

                if device_image_state and \
                    device_image_state.status != "completed":
                    # If device image state is not completed it means
                    # that the image has not been written to the device yet
                    return False
        return True

    def subcloud_firmware_audit(self, subcloud_name, audit_data):
        LOG.info('Triggered firmware audit for: %s.' % subcloud_name)
        if not audit_data:
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                consts.SYNC_STATUS_IN_SYNC)
            LOG.debug('No images to audit, exiting firmware audit')
            return
        try:
            sc_os_client = OpenStackDriver(region_name=subcloud_name,
                                           region_clients=None).keystone_client
            endpoint = sc_os_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(subcloud_name, sc_os_client.session,
                                         endpoint=endpoint)
        except (keystone_exceptions.EndpointNotFound,
                keystone_exceptions.ConnectFailure,
                keystone_exceptions.ConnectTimeout,
                IndexError):
            LOG.exception("Endpoint for online subcloud %s not found, skip "
                          "firmware audit." % subcloud_name)
            return

        # Retrieve all the devices that are present in this subcloud.
        try:
            subcloud_hosts = sysinv_client.get_hosts()
            enabled_host_device_list = []
            for host in subcloud_hosts:
                host_devices = sysinv_client.get_host_device_list(host.uuid)
                for device in host_devices:
                    if device.enabled:
                        enabled_host_device_list.append(device)
        except Exception:
            LOG.exception('Cannot retrieve device image states for subcloud: %s, '
                          'skip firmware audit' % subcloud_name)
            return

        # If there are no enabled devices on the subcloud, then report the
        # sync status as in-sync
        if not enabled_host_device_list:
            LOG.info("No enabled devices on the subcloud %s,"
                     "exiting firmware audit" % subcloud_name)
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                consts.SYNC_STATUS_IN_SYNC)
            return

        # Retrieve the device image states on this subcloud.
        try:
            subcloud_device_image_states = sysinv_client.get_device_image_states()
            LOG.debug("Subcloud %s device_image_states: %s" %
                      (subcloud_name, subcloud_device_image_states))
        except Exception:
            LOG.exception('Cannot retrieve device image states for subcloud: %s, '
                          'skip firmware audit' % subcloud_name)
            return

        # Retrieve device label list for all devices on this subcloud.
        try:
            subcloud_device_label_list = \
                sysinv_client.get_device_label_list()
            LOG.debug("Subcloud %s: subcloud_device_label_list"
                      " fetched" % (subcloud_name))
        except Exception:
            LOG.exception('Cannot retrieve device image states for '
                          'subcloud: %s, skip firmware audit' % subcloud_name)
            return

        out_of_sync = False

        # Check that all device images applied in RegionOne
        # are applied and installed on this subcloud
        # The audit_data for region one is a dictionary
        for image in audit_data:
            # audit_data will be a dict from passing through RPC, so objectify
            image = FirmwareAuditData.from_dict(image)
            proceed = self._check_subcloud_device_has_image(subcloud_name,
                                                            sysinv_client,
                                                            image,
                                                            enabled_host_device_list,
                                                            subcloud_device_image_states,
                                                            subcloud_device_label_list)
            if not proceed:
                out_of_sync = True
                break

        if out_of_sync:
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                consts.SYNC_STATUS_OUT_OF_SYNC)
        else:
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                consts.SYNC_STATUS_IN_SYNC)
        LOG.info('Firmware audit completed for: %s.' % subcloud_name)
