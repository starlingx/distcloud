#
# Copyright (c) 2020-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dccommon.drivers.openstack import vim
from dccommon import exceptions as vim_exc
from dcmanager.common import consts
from dcmanager.common import exceptions
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
            opts_dict[consts.EXTRA_ARGS_RELEASE_ID] = extra_args.get(
                consts.EXTRA_ARGS_RELEASE_ID
            )
            rollback = extra_args.get(consts.EXTRA_ARGS_ROLLBACK)
            opts_dict[consts.EXTRA_ARGS_ROLLBACK] = rollback
            if not rollback:
                opts_dict[consts.EXTRA_ARGS_SNAPSHOT] = extra_args.get(
                    consts.EXTRA_ARGS_SNAPSHOT
                )
                opts_dict[consts.EXTRA_ARGS_DELETE] = extra_args.get(
                    consts.EXTRA_ARGS_WITH_DELETE
                )

        try:
            # Call the API to build the VIM strategy
            # release, snapshot, rollback and delete will be sent as a
            # **kwargs value for sw-deploy strategy
            subcloud_strategy = self.get_vim_client(region).create_strategy(
                self.strategy_name,
                opts_dict["storage-apply-type"],
                opts_dict["worker-apply-type"],
                opts_dict["max-parallel-workers"],
                opts_dict["default-instance-action"],
                opts_dict["alarm-restriction-type"],
                release=opts_dict.get(consts.EXTRA_ARGS_RELEASE_ID),
                snapshot=opts_dict.get(consts.EXTRA_ARGS_SNAPSHOT),
                rollback=opts_dict.get(consts.EXTRA_ARGS_ROLLBACK),
                delete=opts_dict.get(consts.EXTRA_ARGS_DELETE),
            )
        except vim_exc.VIMClientException as exc:
            details = "Failed to create VIM strategy."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.CreateVIMStrategyFailedException,
                exc=exc,
                strategy_name=self.strategy_name,
            )

        # a successful API call to create MUST set the state be 'building'
        if subcloud_strategy.state != vim.STATE_BUILDING:
            details = "Unexpected VIM strategy build state."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.CreateVIMStrategyFailedException,
                state=subcloud_strategy.state,
                strategy_name=self.strategy_name,
            )
        return subcloud_strategy

    def _delete_existing_strategy(self, vim_client, strategy_step):
        self.info_log(strategy_step, "Deleting existing VIM strategy")
        try:
            vim_client.delete_strategy(strategy_name=self.strategy_name)
        except vim_exc.VIMClientException as exc:
            details = "Failed to delete existing VIM strategy."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.CreateVIMStrategyFailedException,
                exc=exc,
                strategy_name=self.strategy_name,
            )

    def _wait_for_strategy_build(self, vim_client, strategy_step):
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise exceptions.StrategyStoppedException()
            if counter >= self.max_queries:
                details = "Timeout building VIM strategy."
                self.handle_exception(
                    strategy_step,
                    details,
                    exceptions.CreateVIMStrategyFailedException,
                    strategy_name=self.strategy_name,
                )
            counter += 1
            time.sleep(self.sleep_duration)

            try:
                # query the vim strategy to see if it is in the new state
                subcloud_strategy = vim_client.get_strategy(
                    strategy_name=self.strategy_name, raise_error_if_missing=True
                )
            except vim_exc.VIMClientException as exc:
                details = "Failed to get VIM strategy."
                self.handle_exception(
                    strategy_step,
                    details,
                    exceptions.CreateVIMStrategyFailedException,
                    exc=exc,
                    strategy_name=self.strategy_name,
                )

            # Check for skip criteria where a failed 'build' might be expected
            # pylint: disable-next=assignment-from-none
            skip_state = self.skip_check(strategy_step, subcloud_strategy)
            if skip_state is not None:
                self.info_log(strategy_step, f"Skip forward to state: {skip_state}")
                self.override_next_state(skip_state)
                # break out of loop. Let overridden 'next_state' take over
                break

            if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
                self.info_log(strategy_step, "VIM strategy has been built")
                break
            elif subcloud_strategy.state in [vim.STATE_BUILDING]:
                # This is the expected state while creating the strategy
                continue
            else:
                error_message = {
                    vim.STATE_BUILD_FAILED: "VIM strategy build failed: ",
                    vim.STATE_BUILD_TIMEOUT: "VIM strategy build timed out: ",
                }.get(subcloud_strategy.state, "VIM strategy unexpected build state. ")

                build_error = (
                    subcloud_strategy.build_phase.response
                    or subcloud_strategy.build_phase.reason
                )
                self.handle_exception(
                    strategy_step,
                    error_message + build_error,
                    exceptions.CreateVIMStrategyFailedException,
                    state=subcloud_strategy.state,
                    strategy_name=self.strategy_name,
                )

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

        try:
            vim_client = self.get_vim_client(region)
        except Exception as exc:
            details = "Get VIM client failed."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.CreateVIMStrategyFailedException,
                exc=exc,
                strategy_name=self.strategy_name,
            )
        try:
            # Get the existing VIM strategy, which may be None
            subcloud_strategy = vim_client.get_strategy(
                strategy_name=self.strategy_name, raise_error_if_missing=False
            )
        except vim_exc.VIMClientException as exc:
            details = "Failed to get VIM strategy."
            self.handle_exception(
                strategy_step,
                details,
                exceptions.CreateVIMStrategyFailedException,
                exc=exc,
                strategy_name=self.strategy_name,
            )

        if subcloud_strategy is None:
            subcloud_strategy = self._create_vim_strategy(strategy_step, region)
        else:
            self.info_log(
                strategy_step,
                f"VIM strategy exists with state: {subcloud_strategy.state}",
            )
            # if a strategy exists in any type of failed state or aborted state it
            # should be deleted. Applied state should also be deleted from previous
            # success runs.
            if subcloud_strategy.state in [
                vim.STATE_BUILDING,
                vim.STATE_APPLYING,
                vim.STATE_ABORTING,
            ]:
                # Can't delete a strategy in these states
                details = (
                    "Failed to create a VIM strategy. There already is an "
                    "existing strategy in this state."
                )
                self.handle_exception(
                    strategy_step,
                    details,
                    exceptions.CreateVIMStrategyFailedException,
                    state=subcloud_strategy.state,
                    strategy_name=self.strategy_name,
                )

            # if strategy exists in any other type of state, delete and create
            self._delete_existing_strategy(vim_client, strategy_step)
            # re-create it
            subcloud_strategy = self._create_vim_strategy(strategy_step, region)

        # A strategy already exists, or is being built.
        # Loop until the strategy is done building Repeatedly query the API
        self._wait_for_strategy_build(vim_client, strategy_step)
        return self.next_state
