#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.firmware import utils
from dcmanager.rpc import client as dcmanager_rpc_client

# When an unlock occurs, a reboot is triggered. During reboot, API calls fail.
# The max time allowed here is 30 minutes (ie: 30 queries with 1 minute sleep)
DEFAULT_MAX_FAILED_QUERIES = 30
DEFAULT_FAILED_SLEEP = 60


class FinishingFwUpdateState(BaseState):
    """State for finishing the firmware update."""

    def __init__(self, region_name):
        super(FinishingFwUpdateState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE, region_name=region_name)
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def align_subcloud_status(self, strategy_step):
        self.info_log(strategy_step,
                      "Setting endpoint status of %s to %s"
                      % (dccommon_consts.ENDPOINT_TYPE_FIRMWARE,
                         dccommon_consts.SYNC_STATUS_IN_SYNC))
        dcmanager_state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        # The subcloud name may differ from the region name in the strategy_step
        dcmanager_state_rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=self.get_subcloud_name(strategy_step),
            subcloud_region=self.get_region_name(strategy_step),
            endpoint_type=dccommon_consts.ENDPOINT_TYPE_FIRMWARE,
            sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)

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
        fail_counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                subcloud_hosts = self.get_sysinv_client(region).get_hosts()
                for host in subcloud_hosts:
                    host_devices = self.get_sysinv_client(
                        region).get_host_device_list(host.uuid)
                    for device in host_devices:
                        if device.enabled:
                            enabled_host_device_list.append(device)
                break
            except Exception:
                if fail_counter >= self.max_failed_queries:
                    raise Exception("Timeout waiting to query subcloud hosts")
                fail_counter += 1
                time.sleep(self.failed_sleep_duration)

        if not enabled_host_device_list:
            # There are no enabled devices in this subcloud, so break out
            # of this handler, since there will be nothing examine
            self.info_log(strategy_step, "No enabled devices.")
            # This is the final state for this subcloud. set it to in-sync
            self.align_subcloud_status(strategy_step)
            return self.next_state

        fail_counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                # determine list of applied subcloud images
                subcloud_images = self.get_sysinv_client(region).get_device_images()
                applied_subcloud_images = \
                    utils.filter_applied_images(subcloud_images,
                                                expected_value=True)
                # Retrieve the device image states on this subcloud.
                subcloud_device_image_states = self.get_sysinv_client(
                    region).get_device_image_states()
                break
            except Exception:
                # TODO(rlima): Invert the fail counter with the validation to fix
                # the unit tests, because it's always greater than the
                # DEFAULT_MAX_FAILED_QUERIES
                if fail_counter >= self.max_failed_queries:
                    raise Exception(
                        "Timeout waiting to query subcloud device image info")
                fail_counter += 1
                time.sleep(self.failed_sleep_duration)

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
