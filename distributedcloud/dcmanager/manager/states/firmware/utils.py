#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os

# Device Image Status - duplicated from sysinv/common/device.py
DEVICE_IMAGE_UPDATE_PENDING = 'pending'
DEVICE_IMAGE_UPDATE_IN_PROGRESS = 'in-progress'
DEVICE_IMAGE_UPDATE_IN_PROGRESS_ABORTED = 'in-progress-aborted'
DEVICE_IMAGE_UPDATE_COMPLETED = 'completed'
DEVICE_IMAGE_UPDATE_FAILED = 'failed'
DEVICE_IMAGE_UPDATE_NULL = ''


# convert a list of objects that have a uuid field, into a map keyed on uuid
def to_uuid_map(list_with_uuids):
    uuid_map = {}
    for uuid_obj in list_with_uuids:
        uuid_map[uuid_obj.uuid] = uuid_obj
    return uuid_map


# todo(abailey) refactor based on firmware_audit code for
# _check_subcloud_device_has_image
# THIS METHOD should be renamed !!
def check_subcloud_device_has_image(image,
                                    enabled_host_device_list,
                                    subcloud_device_label_list):
    """Return device on subcloud that matches the image, or None"""

    apply_to_all_devices = False
    if image.applied_labels:
        # Returns true if the list contains at least one empty dict.
        # An empty dict signifies that image is to be applied to
        # all devices that match the pci vendor and pci device ID.
        apply_to_all_devices = any(not image for image in image.applied_labels)

    for device in enabled_host_device_list:
        if not apply_to_all_devices:
            # If image has to be applied to devices with a matching label
            # and the device label list is empty on the subcloud, there
            # cannot be a match. break out of the loop and return None
            if not subcloud_device_label_list:
                break
            # Device is considered eligible if device labels
            # match at least one of the image labels
            is_device_eligible = False
            for image_label in image.applied_labels:
                label_key = list(image_label.keys())[0]
                label_value = image_label.get(label_key)
                is_device_eligible = check_for_label_match(
                    subcloud_device_label_list,
                    device.uuid,
                    label_key,
                    label_value)
                # If device label matches any image label stop checking
                # for any other label matches and do pci comparison below
                if is_device_eligible:
                    break

            # If this device is not eligible, go to the next device
            if not is_device_eligible:
                continue

        # We found an eligible device
        if image.pci_vendor == device.pvendor_id and \
           image.pci_device == device.pdevice_id:
            return device

    # no matching devices
    return None


# todo(abailey): refactor with https://review.opendev.org/#/c/741515
def get_device_image_filename(resource):
    filename = "{}-{}-{}-{}.bit".format(resource.bitstream_type,
                                        resource.pci_vendor,
                                        resource.pci_device,
                                        resource.uuid)
    return filename


# todo(abailey): use constant from https://review.opendev.org/#/c/741515
def determine_image_file(image):
    """Find the bitstream file for an image in the vault"""
    DEVICE_IMAGE_VAULT_DIR = '/opt/dc-vault/device_images'
    return os.path.join(DEVICE_IMAGE_VAULT_DIR,
                        get_device_image_filename(image))


def determine_image_fields(image):
    """Return the appropriate upload fields for an image"""
    field_list = ['uuid',
                  'bitstream_type',
                  'pci_vendor',
                  'pci_device',
                  'bitstream_id',
                  'key_signature',
                  'revoke_key_id',
                  'name',
                  'description',
                  'image_version']
    fields = dict((k, v) for (k, v) in vars(image).items()
                  if k in field_list and not (v is None))
    return fields


def check_for_label_match(subcloud_host_device_label_list,
                          device_uuid,
                          label_key,
                          label_value):
    # todo(abailey): should this compare pci_device_uuid or vendor/device
    for device_label in subcloud_host_device_label_list:
        if device_label.pcidevice_uuid and \
            device_uuid == device_label.pcidevice_uuid and \
            label_key == device_label.label_key and \
            label_value == device_label.label_value:
                return True
    return False


def filter_applied_images(device_images, expected_value=True):
    """Filter a list of DeviceImage objects by the 'applied' field

       Returns list of images that have 'applied' field matching expected_value
    """
    filtered_images = []
    for device_image in device_images:
        if device_image.applied == expected_value:
            filtered_images.append(device_image)
    return filtered_images
