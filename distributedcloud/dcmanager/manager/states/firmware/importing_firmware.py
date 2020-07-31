#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os

from dcmanager.common import consts
from dcmanager.manager.states.base import BaseState
from dcmanager.manager.states.firmware import utils


class ImportingFirmwareState(BaseState):
    """State for importing firmware

       Query the device-images on the system controller that are 'pending'
       Ensure those device images are uploaded on the subcloud.
    """

    def __init__(self):
        super(ImportingFirmwareState, self).__init__(
            next_state=consts.STRATEGY_STATE_CREATING_FW_UPDATE_STRATEGY)

    def _image_in_list(self, image, image_list):
        # todo(abailey): FUTURE. There may be other ways that two images can
        # be considered identical other than a database UUID
        for img in image_list:
            if img.uuid == image.uuid:
                return True
        return False

    def perform_state_action(self, strategy_step):
        """Import firmware on a subcloud

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        # The comparisons in this method need to align with the logic in
        # subcloud_firmware_audit

        # ==============  query system controller images ==============
        system_controller_images = self.get_sysinv_client(
            consts.DEFAULT_REGION_NAME).get_device_images()
        # determine list of applied system controller images
        applied_system_controller_images = \
            utils.filter_applied_images(system_controller_images,
                                        expected_value=True)

        # ============== query subcloud images ========================
        region = self.get_region_name(strategy_step)
        subcloud_images = self.get_sysinv_client(
            region).get_device_images()
        # determine list of applied subcloud images
        applied_subcloud_images = \
            utils.filter_applied_images(subcloud_images,
                                        expected_value=True)

        subcloud_device_label_list = self.get_sysinv_client(
            region).get_device_label_list()

        subcloud_labels = []
        for device_label in subcloud_device_label_list:
            subcloud_labels.append({device_label.label_key:
                                    device_label.label_value})
        # - remove any applied images in subcloud that are not applied on the
        # system controller
        for image in applied_subcloud_images:
            if not self._image_in_list(image,
                                       applied_system_controller_images):
                # the applied image in the subcloud is not in the system
                # controller applied list, and should be removed
                # Use the existing labels on the image for the remove
                labels = []
                for label in image.applied_labels:
                    # Do not append an empty dictionary
                    if label:
                        labels.append(label)
                self.info_log(strategy_step,
                              "Remove Image %s by labels: %s" % (image.uuid,
                                                                 str(labels)))
                self.get_sysinv_client(region).remove_device_image(
                    image.uuid,
                    labels)

        # get the list of enabled devices on the subcloud
        enabled_host_device_list = []
        subcloud_hosts = self.get_sysinv_client(region).get_hosts()
        for host in subcloud_hosts:
            host_devices = self.get_sysinv_client(
                region).get_host_device_list(host.uuid)
            for device in host_devices:
                if device.enabled:
                    enabled_host_device_list.append(device)

        if not enabled_host_device_list:
            # There are no enabled devices in this subcloud, so break out
            # of this handler, since there will be nothing to upload or apply
            self.info_log(strategy_step,
                          "No enabled devices. Skipping upload and apply.")
            return self.next_state

        # Retrieve the device image states on this subcloud.
        subcloud_device_image_states = self.get_sysinv_client(
            region).get_device_image_states()

        # go through the applied images on system controller
        # any of the images that correspond to an enabled device on the
        # subcloud should be uploaded and applied if it does not exist
        for image in applied_system_controller_images:
            device = utils.check_subcloud_device_has_image(
                image,
                enabled_host_device_list,
                subcloud_device_label_list)
            if device is not None:
                # there was a matching device for that image
                # We need to upload it if it does not exist yet
                if not self._image_in_list(image, subcloud_images):
                    self.info_log(strategy_step,
                                  "Uploading image:%s " % image.uuid)
                    bitstreamfile = utils.determine_image_file(image)
                    if not os.path.isfile(bitstreamfile):
                        # We could not find the file in the vault
                        raise Exception("File does not exist: %s"
                                        % bitstreamfile)
                    fields = utils.determine_image_fields(image)
                    new_image_response = self.get_sysinv_client(
                        region).upload_device_image(bitstreamfile, fields)
                    self.debug_log(strategy_step,
                                   "Upload device image returned: %s"
                                   % str(new_image_response))
                    self.info_log(strategy_step,
                                  "Uploaded image:%s " % image.uuid)

                # The image exists on the subcloud
                # However, it may not have been applied to this device
                device_image_state = None
                for device_image_state_obj in subcloud_device_image_states:
                    if device_image_state_obj.pcidevice_uuid == device.uuid\
                        and device_image_state_obj.image_uuid == image.uuid:
                        device_image_state = device_image_state_obj
                        break
                else:
                    # If no device image state is present in the list that
                    # means the image hasn't been applied yet

                    # apply with ALL the labels declared for this image on
                    # system controller
                    labels = []
                    for label in image.applied_labels:
                        # Do not append an empty dictionary
                        if label:
                            labels.append(label)
                    self.info_log(strategy_step,
                                  "Applying device image:%s with labels:%s"
                                  % (image.uuid, str(labels)))

                    apply_response = self.get_sysinv_client(
                        region).apply_device_image(image.uuid, labels=labels)
                    self.debug_log(strategy_step,
                                   "Apply device image returned: %s"
                                   % str(apply_response))
                    self.info_log(strategy_step,
                                  "Applied image:%s with labels:%s"
                                  % (image.uuid, str(labels)))
                    continue

                # We have a device_image_state. Lets examine the apply status
                if device_image_state.status != utils.DEVICE_IMAGE_UPDATE_COMPLETED:
                    self.info_log(strategy_step,
                                  "Image:%s has not been written. State:%s"
                                  % (image.uuid, device_image_state.status))
                else:
                    self.info_log(strategy_step,
                                  "Skipping already applied image:%s "
                                  % image.uuid)

        # If none of those API calls failed, this state was successful
        # Success, state machine can proceed to the next state
        return self.next_state
