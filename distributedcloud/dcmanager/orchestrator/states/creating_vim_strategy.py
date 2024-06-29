#
# Copyright (c) 2020-2021, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState

# Max time: 30 minutes = 180 queries x 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class CreatingVIMStrategyState(BaseState):
    """State for creating the VIM strategy."""

    def __init__(self, next_state, region_name, strategy_name):
        super().__init__(next_state=next_state, region_name=region_name)
        self.strategy_name = strategy_name
        # max time to wait for the strategy to be built (in seconds)
        # is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def _create_vim_strategy(self, strategy_step, region):
        self.info_log(strategy_step, "Creating (%s) VIM strategy" % self.strategy_name)

        # Get the update options
        opts_dict = utils.get_sw_update_opts(
            self.context, for_sw_update=True, subcloud_id=strategy_step.subcloud_id
        )

        # Get release parameter data for sw-deploy strategy
        if self.strategy_name == vim.STRATEGY_NAME_SW_USM:
            extra_args = utils.get_sw_update_strategy_extra_args(self.context)
            release_id = extra_args.get(consts.EXTRA_ARGS_RELEASE_ID)
            opts_dict["release_id"] = release_id
            # Create rollback = False since DC orchestration do not support rollback
            opts_dict["rollback"] = False

        # Call the API to build the VIM strategy
        # release and rollback will be sent as a **kwargs value for sw-deploy strategy
        subcloud_strategy = self.get_vim_client(region).create_strategy(
            self.strategy_name,
            opts_dict["storage-apply-type"],
            opts_dict["worker-apply-type"],
            opts_dict["max-parallel-workers"],
            opts_dict["default-instance-action"],
            opts_dict["alarm-restriction-type"],
            release=opts_dict.get("release_id"),
            rollback=opts_dict.get("rollback"),
        )

        # a successful API call to create MUST set the state be 'building'
        if subcloud_strategy.state != vim.STATE_BUILDING:
            raise Exception(
                "Unexpected VIM strategy build state: %s" % subcloud_strategy.state
            )
        return subcloud_strategy

    def skip_check(self, strategy_step, subcloud_strategy):
        """Subclasses can override this to allow this state to skip ahead"""
        return None

    def perform_state_action(self, strategy_step):
        """Create a VIM strategy using VIM REST API

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        region = self.get_region_name(strategy_step)

        # Get the existing VIM strategy, which may be None
        subcloud_strategy = self.get_vim_client(region).get_strategy(
            strategy_name=self.strategy_name, raise_error_if_missing=False
        )

        if subcloud_strategy is None:
            subcloud_strategy = self._create_vim_strategy(strategy_step, region)
        else:
            self.info_log(
                strategy_step,
                "VIM strategy exists with state: %s" % subcloud_strategy.state,
            )
            # if a strategy exists in any type of failed state or aborted
            # state it should be deleted.
            # applied state should also be deleted from previous success runs.
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
            self.info_log(strategy_step, "Deleting existing VIM strategy")
            self.get_vim_client(region).delete_strategy(
                strategy_name=self.strategy_name
            )
            # re-create it
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
                strategy_name=self.strategy_name, raise_error_if_missing=True
            )

            # Check for skip criteria where a failed 'build' might be expected
            # pylint: disable-next=assignment-from-none
            skip_state = self.skip_check(strategy_step, subcloud_strategy)
            if skip_state is not None:
                self.info_log(strategy_step, "Skip forward to state:(%s)" % skip_state)
                self.override_next_state(skip_state)
                # break out of loop. Let overridden 'next_state' take over
                break

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
