#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.manager.states.base import BaseState
from dcmanager.manager.states.firmware import utils


class FinishingFwUpdateState(BaseState):
    """State for finishing the firmware update."""

    def __init__(self):
        super(FinishingFwUpdateState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE)

    def perform_state_action(self, strategy_step):
        """Finish the firmware update.

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        # Possible things that need to be done in this state:
        # - delete the vim fw update strategy
        # - clean up files
        # - report information about the firmware on the subcloud

        region = self.get_region_name(strategy_step)

        # Get the existing firmware strategy, which may be None
        subcloud_strategy = self.get_vim_client(region).get_strategy(
            strategy_name=vim.STRATEGY_NAME_FW_UPDATE,
            raise_error_if_missing=False)

        if subcloud_strategy is not None:
            self.info_log(strategy_step,
                          "Deleting FW VIM strategy that has state: %s"
                          % subcloud_strategy.state)
            self.get_vim_client(region).delete_strategy(
                strategy_name=vim.STRATEGY_NAME_FW_UPDATE)

        # FINAL CHECK
        # if any of the device images are in failed state, fail this state
        # only check for enabled devices matching images with applied labels

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
            # of this handler, since there will be nothing examine
            self.info_log(strategy_step, "No enabled devices.")
            return self.next_state

        # determine list of applied subcloud images
        subcloud_images = self.get_sysinv_client(region).get_device_images()
        applied_subcloud_images = \
            utils.filter_applied_images(subcloud_images,
                                        expected_value=True)
        # Retrieve the device image states on this subcloud.
        subcloud_device_image_states = self.get_sysinv_client(
            region).get_device_image_states()

        device_map = utils.to_uuid_map(enabled_host_device_list)
        image_map = utils.to_uuid_map(applied_subcloud_images)
        # loop over all states to see which are not complete
        # if any correspond to an enabled device, fail this handler
        failed_states = []
        for device_image_state_obj in subcloud_device_image_states:
            if device_image_state_obj.status != utils.DEVICE_IMAGE_UPDATE_COMPLETED:
                device = device_map.get(device_image_state_obj.pcidevice_uuid)
                if device is not None:
                    image = image_map.get(device_image_state_obj.image_uuid)
                    if image is not None:
                        self.info_log(strategy_step,
                                      "Failed apply: %s"
                                      % device_image_state_obj)
                        failed_states.append(device_image_state_obj)
        if failed_states:
            # todo(abailey): create a custom Exception
            raise Exception("Not all images applied successfully")

        # Success, state machine can proceed to the next state
        return self.next_state
