#
# Copyright (c) 2020, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils as dcmanager_utils
from dcmanager.orchestrator.states.base import BaseState

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class CreatingVIMStrategyState(BaseState):
    """State for creating the VIM FPGA update strategy."""

    def __init__(self, region_name, strategy):
        super(CreatingVIMStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_APPLYING_FW_UPDATE_STRATEGY,
            region_name=region_name,
            strategy=strategy,
        )
        # max time to wait for the strategy to be built (in seconds)
        # is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def _create_vim_strategy(self, strategy_step, region):
        self.info_log(strategy_step, "Creating VIM firmware strategy")

        # Get the update options
        opts_dict = dcmanager_utils.get_sw_update_opts(
            self.context, for_sw_update=True, subcloud_id=strategy_step.subcloud_id
        )

        # Call the API to build the firmware strategy
        # max-parallel-workers cannot be less than 2 or greater than 5
        subcloud_strategy = self.get_vim_client(region).create_strategy(
            vim.STRATEGY_NAME_FW_UPDATE,
            opts_dict["storage-apply-type"],
            opts_dict["worker-apply-type"],
            2,  # opts_dict['max-parallel-workers'],
            opts_dict["default-instance-action"],
            opts_dict["alarm-restriction-type"],
        )

        # a successful API call to create MUST set the state be 'building'
        if subcloud_strategy.state != vim.STATE_BUILDING:
            raise Exception(
                "Unexpected VIM strategy build state: %s" % subcloud_strategy.state
            )
        return subcloud_strategy

    def perform_state_action(self, strategy_step):
        """Create a FPGA update strategy using VIM REST API

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        region = self.get_region_name(strategy_step)

        # Get the existing firmware strategy, which may be None
        subcloud_strategy = self.get_vim_client(region).get_strategy(
            strategy_name=vim.STRATEGY_NAME_FW_UPDATE, raise_error_if_missing=False
        )

        if subcloud_strategy is None:
            subcloud_strategy = self._create_vim_strategy(strategy_step, region)
        else:
            self.info_log(
                strategy_step,
                "FW VIM strategy already exists with state: %s"
                % subcloud_strategy.state,
            )
            # if a strategy exists in building/applying/aborting do not delete
            # it and instead raise an exception
            if subcloud_strategy.state in [
                vim.STATE_BUILDING,
                vim.STATE_APPLYING,
                vim.STATE_ABORTING,
            ]:
                # Can't delete a strategy in these states
                message = (
                    "Failed to create a VIM strategy for %s. "
                    "There already is an existing strategy in %s state"
                    % (region, subcloud_strategy.state)
                )
                self.warn_log(strategy_step, message)
                raise Exception(message)

            # if strategy exists in any other type of state, delete and create
            self.info_log(strategy_step, "Deleting existing FW VIM strategy")
            self.get_vim_client(region).delete_strategy(
                strategy_name=vim.STRATEGY_NAME_FW_UPDATE
            )
            subcloud_strategy = self._create_vim_strategy(strategy_step, region)

        # A strategy already exists, or is being built
        # Loop until the strategy is done building Repeatedly query the API
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            if counter >= self.max_queries:
                raise Exception(
                    "Timeout building vim strategy. state: %s" % subcloud_strategy.state
                )
            counter += 1
            time.sleep(self.sleep_duration)

            # query the vim strategy to see if it is in the new state
            subcloud_strategy = self.get_vim_client(region).get_strategy(
                strategy_name=vim.STRATEGY_NAME_FW_UPDATE, raise_error_if_missing=True
            )
            if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
                self.info_log(strategy_step, "VIM strategy has been built")
                break
            elif subcloud_strategy.state == vim.STATE_BUILDING:
                # This is the expected state while creating the strategy
                pass
            elif subcloud_strategy.state == vim.STATE_BUILD_FAILED:
                raise Exception(
                    "VIM strategy build failed: %s. %s."
                    % (subcloud_strategy.state, subcloud_strategy.build_phase.reason)
                )
            elif subcloud_strategy.state == vim.STATE_BUILD_TIMEOUT:
                raise Exception(
                    "VIM strategy build timed out: %s." % subcloud_strategy.state
                )
            else:
                raise Exception(
                    "VIM strategy unexpected build state: %s" % subcloud_strategy.state
                )

        # Success, state machine can proceed to the next state
        return self.next_state
