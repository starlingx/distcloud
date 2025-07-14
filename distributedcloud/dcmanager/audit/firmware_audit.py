# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
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

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache
from dccommon import utils as cutils
from dcmanager.common import consts

LOG = logging.getLogger(__name__)


class FirmwareAuditData(object):
    def __init__(
        self,
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
            "bitstream_type": self.bitstream_type,
            "bitstream_id": self.bitstream_id,
            "bmc": self.bmc,
            "retimer_included": self.retimer_included,
            "key_signature": self.key_signature,
            "revoke_key_id": self.revoke_key_id,
            "applied": self.applied,
            "pci_vendor": self.pci_vendor,
            "pci_device": self.pci_device,
            "applied_labels": self.applied_labels,
        }

    @classmethod
    def from_dict(cls, values):
        if values is None:
            return None
        return cls(**values)


class FirmwareAudit(object):
    """Manages tasks related to firmware audits."""

    def __init__(self):
        LOG.debug("FirmwareAudit initialization...")
        self.audit_count = 0

    def get_regionone_audit_data(self):
        """Query RegionOne to determine what device images have to be applied

        to the system

        :return: A list of device images applied on the system controller

        """
        try:
            admin_session = EndpointCache.get_admin_session()
            sysinv_client = SysinvClient(
                region=cutils.get_region_one_name(), session=admin_session
            )
        except Exception:
            LOG.exception("Failure initializing Sysinv Client, skip firmware audit.")
            return None

        filtered_images = []
        try:
            # get_device_images is a list of DeviceImage objects
            local_device_images = sysinv_client.get_device_images()

            # Filter images which have been applied on RegionOne
            for image in local_device_images:
                if image.applied:
                    filtered_images.append(
                        FirmwareAuditData(
                            image.bitstream_type,
                            image.bitstream_id,
                            image.bmc,
                            image.retimer_included,
                            image.key_signature,
                            image.revoke_key_id,
                            image.applied,
                            image.pci_vendor,
                            image.pci_device,
                            image.applied_labels,
                        )
                    )
            LOG.debug("RegionOne applied_images: %s" % filtered_images)
        except Exception:
            LOG.exception(
                "Cannot retrieve device images for RegionOne, skip firmware audit"
            )
        return filtered_images

    @staticmethod
    def _check_for_label_match(
        subcloud_host_device_label_list, device_uuid, label_key, label_value
    ):
        for device_label in subcloud_host_device_label_list:
            if (
                device_label.pcidevice_uuid
                and device_uuid == device_label.pcidevice_uuid
                and label_key == device_label.label_key
                and label_value == device_label.label_value
            ):
                return True
        return False

    @staticmethod
    def _check_image_match(subcloud_image, system_controller_image):
        if (
            (
                system_controller_image.bitstream_type == consts.BITSTREAM_TYPE_ROOT_KEY
                and system_controller_image.key_signature
                == subcloud_image.key_signature
            )
            or (
                system_controller_image.bitstream_type
                == consts.BITSTREAM_TYPE_FUNCTIONAL
                and system_controller_image.bitstream_id == subcloud_image.bitstream_id
                and system_controller_image.bmc == subcloud_image.bmc
                and system_controller_image.retimer_included
                == subcloud_image.retimer_included
            )
            or (
                system_controller_image.bitstream_type
                == consts.BITSTREAM_TYPE_KEY_REVOCATION
                and system_controller_image.revoke_key_id
                == subcloud_image.revoke_key_id
            )
        ):
            return True
        return False

    @classmethod
    def _check_subcloud_device_has_image(
        cls,
        subcloud_name,
        image,
        enabled_host_device_list,
        subcloud_device_image_states,
        subcloud_device_label_list,
        subcloud_device_images,
    ):
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
                    is_device_eligible = cls._check_for_label_match(
                        subcloud_device_label_list, device.uuid, label_key, label_value
                    )
                    # If device label matches any image label stop checking
                    # for any other label matches
                    if is_device_eligible:
                        break

                # If this device is not eligible, go to the next device
                if not is_device_eligible:
                    continue

            if (
                image.pci_vendor == device.pvendor_id
                and image.pci_device == device.pdevice_id
            ):
                device_image_state = None
                subcloud_image = None
                for device_image_state_obj in subcloud_device_image_states:
                    if device_image_state_obj.pcidevice_uuid == device.uuid:
                        try:
                            uuid = device_image_state_obj.image_uuid
                            subcloud_image = subcloud_device_images[uuid]
                        except Exception:
                            msg = "Cannot retrieve device image, skip firmware audit."
                            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
                            return False

                        if cls._check_image_match(subcloud_image, image):
                            device_image_state = device_image_state_obj
                            break
                else:
                    # If no device image state is present in the list that
                    # means the image hasn't been applied yet
                    return False

                if device_image_state and device_image_state.status != "completed":
                    # If device image state is not completed it means
                    # that the image has not been written to the device yet
                    return False
        return True

    @classmethod
    def get_subcloud_audit_data(
        cls,
        sysinv_client: SysinvClient,
        subcloud_name: str = None,
    ):
        enabled_host_device_list = None
        subcloud_device_image_states = None
        subcloud_device_label_list = None
        subcloud_device_images = None
        skip_audit = 4 * [dccommon_consts.SKIP_AUDIT]
        # Retrieve all the devices that are present in this subcloud.
        try:
            enabled_host_device_list = []
            host_devices = sysinv_client.get_all_hosts_device_list()
            for device in host_devices:
                if device.enabled:
                    enabled_host_device_list.append(device)
        except Exception:
            msg = "Cannot retrieve host device list, skip firmware audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit

        # If there are no enabled devices on the subcloud, exit the firmware audit
        if not enabled_host_device_list:
            return enabled_host_device_list, None, None, None

        # Retrieve the device image states on this subcloud.
        try:
            subcloud_device_image_states = sysinv_client.get_device_image_states()
            msg = f"Device_image_states: {subcloud_device_image_states}"
            cutils.log_subcloud_msg(LOG.debug, msg, subcloud_name)
        except Exception:
            msg = "Cannot retrieve device image states, skip firmware audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit

        # Retrieve device label list for all devices on this subcloud.
        try:
            subcloud_device_label_list = sysinv_client.get_device_label_list()
            msg = f"Subcloud_device_label_list: {subcloud_device_label_list}"
            cutils.log_subcloud_msg(LOG.debug, msg, subcloud_name)
        except Exception:
            msg = "Cannot retrieve device label list, skip firmware audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit

        # Retrieve the device images on this subcloud.
        try:
            subcloud_device_images = sysinv_client.get_device_images()
            if subcloud_device_images:
                subcloud_device_images = {
                    image.uuid: image for image in subcloud_device_images
                }
            msg = f"Device_images: {subcloud_device_images}"
            cutils.log_subcloud_msg(LOG.debug, msg, subcloud_name)
        except Exception:
            msg = "Cannot retrieve device images, skip firmware audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit

        return (
            enabled_host_device_list,
            subcloud_device_image_states,
            subcloud_device_label_list,
            subcloud_device_images,
        )

    @classmethod
    def get_subcloud_sync_status(
        cls,
        sysinv_client: SysinvClient,
        audit_data,
        subcloud_name: str = None,
    ):

        subcloud_audit_data = cls.get_subcloud_audit_data(sysinv_client, subcloud_name)
        if dccommon_consts.SKIP_AUDIT in subcloud_audit_data:
            return None
        (
            enabled_host_device_list,
            subcloud_device_image_states,
            subcloud_device_label_list,
            subcloud_device_images,
        ) = subcloud_audit_data

        # If there are no enabled devices on the subcloud, then report the
        # sync status as in-sync
        if not enabled_host_device_list:
            msg = "No enabled devices on the subcloud, exiting firmware audit"
            cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
            return dccommon_consts.SYNC_STATUS_IN_SYNC
        elif enabled_host_device_list == dccommon_consts.SKIP_AUDIT:
            return None

        # Check that all device images applied in RegionOne
        # are applied and installed on this subcloud
        # The audit_data for region one is a dictionary
        for image in audit_data:
            # audit_data will be a dict from passing through RPC/api, so objectify
            image = FirmwareAuditData.from_dict(image)
            proceed = cls._check_subcloud_device_has_image(
                subcloud_name,
                image,
                enabled_host_device_list,
                subcloud_device_image_states,
                subcloud_device_label_list,
                subcloud_device_images,
            )
            if not proceed:
                return dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        return dccommon_consts.SYNC_STATUS_IN_SYNC
