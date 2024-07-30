#
# Copyright (c) 2020, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState


# Applying the vim update strategy may result in a loss of communication
# where API calls fail. The max time in this phase is 30 minutes
# (30 queries with 1 minute sleep)
DEFAULT_MAX_FAILED_QUERIES = 30

# Max time: 60 minutes = 60 queries x 60 seconds
# This is the max time for the state to change completion progress percent
DEFAULT_MAX_WAIT_ATTEMPTS = 60

# each loop while waiting for the apply will sleep for 60 seconds
WAIT_INTERVAL = 60


class ApplyingVIMStrategyState(BaseState):
    """State for creating the VIM FPGA update strategy."""

    def __init__(self, region_name):
        super(ApplyingVIMStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_FINISHING_FW_UPDATE,
            region_name=region_name,
        )
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.wait_attempts = DEFAULT_MAX_WAIT_ATTEMPTS
        self.wait_interval = WAIT_INTERVAL

    def perform_state_action(self, strategy_step):
        """Apply a FPGA update strategy using VIM REST API

        This code derives from patch orchestration: do_apply_subcloud_strategy

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        region = self.get_region_name(strategy_step)

        # query the vim strategy.
        # Do not raise the default exception if there is no strategy
        # because the default exception is unclear: ie: "Get strategy failed"
        subcloud_strategy = self.get_vim_client(region).get_strategy(
            strategy_name=vim.STRATEGY_NAME_FW_UPDATE, raise_error_if_missing=False
        )

        if subcloud_strategy is None:
            self.info_log(strategy_step, "Skip. There is no strategy to apply")
            return self.next_state

        # We have a VIM strategy, but need to check if it is ready to apply
        if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
            # An exception here will fail this state
            subcloud_strategy = self.get_vim_client(region).apply_strategy(
                strategy_name=vim.STRATEGY_NAME_FW_UPDATE
            )
            if subcloud_strategy.state == vim.STATE_APPLYING:
                self.info_log(strategy_step, "VIM Strategy apply in progress")
            else:
                raise Exception(
                    "VIM strategy apply failed - unexpected strategy state %s"
                    % subcloud_strategy.state
                )

        # wait for the new strategy to apply or an existing strategy.
        # Loop until the strategy applies. Repeatedly query the API
        # This can take a long time.
        # Waits for up to 60 minutes for the current phase or completion
        # percentage to change before giving up.

        wait_count = 0
        get_fail_count = 0
        last_details = ""
        while True:
            # todo(abailey): combine the sleep and stop check into one method
            # which would allow the longer 60 second sleep to be broken into
            # multiple smaller sleep calls

            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            # break out of the loop if the max number of attempts is reached
            wait_count += 1
            if wait_count >= self.wait_attempts:
                raise Exception("Timeout applying firmware strategy.")
            # every loop we wait, even the first one
            time.sleep(self.wait_interval)

            # get the strategy
            try:
                subcloud_strategy = self.get_vim_client(region).get_strategy(
                    strategy_name=vim.STRATEGY_NAME_FW_UPDATE,
                    raise_error_if_missing=False,
                )
                get_fail_count = 0
            except Exception:
                # When applying the strategy to a subcloud, the VIM can
                # be unreachable for a significant period of time when
                # there is a controller swact, or in the case of AIO-SX,
                # when the controller reboots.
                get_fail_count += 1
                if get_fail_count >= self.max_failed_queries:
                    # We have waited too long.
                    raise Exception(
                        "Timeout during recovery of apply firmware strategy."
                    )
                self.debug_log(
                    strategy_step,
                    "Unable to get firmware strategy - attempt %d" % get_fail_count,
                )
                continue
            # The loop gets here if the API is able to respond
            # Check if the strategy no longer exists. This should not happen.
            if subcloud_strategy is None:
                raise Exception("Firmware strategy disappeared while applying")
            elif subcloud_strategy.state == vim.STATE_APPLYING:
                # Still applying. Update details if it has changed
                new_details = "%s phase is %s%% complete" % (
                    subcloud_strategy.current_phase,
                    subcloud_strategy.current_phase_completion_percentage,
                )
                if new_details != last_details:
                    # Progress is being made.
                    # Reset the counter and log the progress
                    last_details = new_details
                    wait_count = 0
                    self.info_log(strategy_step, new_details)
                    db_api.strategy_step_update(
                        self.context, strategy_step.subcloud_id, details=new_details
                    )
            elif subcloud_strategy.state == vim.STATE_APPLIED:
                # Success. Break out of loop
                self.info_log(strategy_step, "Firmware strategy has been applied")
                break
            elif subcloud_strategy.state in [
                vim.STATE_APPLY_FAILED,
                vim.STATE_APPLY_TIMEOUT,
            ]:
                # Explicit known failure states
                raise Exception(
                    "Firmware strategy apply failed. %s. %s"
                    % (subcloud_strategy.state, subcloud_strategy.apply_phase.reason)
                )
            else:
                # Other states are bad
                raise Exception(
                    "Firmware strategy apply failed. Unexpected State: %s."
                    % subcloud_strategy.state
                )
            # end of loop

        # Success, state machine can proceed to the next state
        return self.next_state
