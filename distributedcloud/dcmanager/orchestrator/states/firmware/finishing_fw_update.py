#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.firmware import utils
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.common import consts as dcorch_consts


class FinishingFwUpdateState(BaseState):
    """State for finishing the firmware update."""

    def __init__(self, region_name):
        super(FinishingFwUpdateState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE, region_name=region_name)

    def align_subcloud_status(self, strategy_step):
        self.info_log(strategy_step,
                      "Setting endpoint status of %s to %s"
                      % (dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
                         consts.SYNC_STATUS_IN_SYNC))
        rpc_client = dcmanager_rpc_client.ManagerClient()
        # The subcloud name is the same as the region in the strategy_step
        rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=self.get_region_name(strategy_step),
            endpoint_type=dcorch_consts.ENDPOINT_TYPE_FIRMWARE,
            sync_status=consts.SYNC_STATUS_IN_SYNC)

    def perform_state_action(self, strategy_step):
        """Finish the firmware update.

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        # Possible things that need to be done in this state:
        # - clean up files
        # - report information about the firmware on the subcloud

        region = self.get_region_name(strategy_step)

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
            # This is the final state for this subcloud. set it to in-sync
            self.align_subcloud_status(strategy_step)
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

        # This is the final state for this subcloud. set it to in-sync
        self.align_subcloud_status(strategy_step)
        # Success, state machine can proceed to the next state
        return self.next_state
