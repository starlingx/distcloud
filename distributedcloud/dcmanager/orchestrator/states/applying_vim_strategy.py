#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import exceptions
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
    """State for applying the VIM strategy."""

    def __init__(
        self,
        next_state,
        region_name,
        strategy_name,
        wait_attempts=DEFAULT_MAX_WAIT_ATTEMPTS,
        wait_interval=WAIT_INTERVAL,
    ):
        super(ApplyingVIMStrategyState, self).__init__(
            next_state=next_state, region_name=region_name
        )
        self.strategy_name = strategy_name
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.wait_attempts = wait_attempts
        self.wait_interval = wait_interval

    def perform_state_action(self, strategy_step):
        """Apply a VIM strategy using VIM REST API

        This code derives from patch orchestration: do_apply_subcloud_strategy

        Any client (vim, sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.

        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        region = self.get_region_name(strategy_step)

        if self.strategy_name == vim.STRATEGY_NAME_SW_USM:
            # Update the subcloud deploy_status to indicate that the sw-deploy
            # strategy is being applied
            db_api.subcloud_update(
                self.context,
                strategy_step.subcloud_id,
                deploy_status=consts.DEPLOY_STATE_SW_DEPLOY_IN_PROGRESS,
            )

        # query the vim strategy. Check if it is None
        subcloud_strategy = self.get_vim_client(region).get_strategy(
            strategy_name=self.strategy_name, raise_error_if_missing=False
        )

        # Do not raise the default exception if there is no strategy
        # because the default exception is unclear: ie: "Get strategy failed"
        if subcloud_strategy is None:
            message = "VIM Strategy not found."
            raise exceptions.ApplyVIMStrategyFailedException(
                subcloud=strategy_step.subcloud.name,
                name=self.strategy_name,
                state=subcloud_strategy.state,
                details=message,
            )

        # We have a VIM strategy, but need to check if it is ready to apply
        elif subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
            # An exception here will fail this state
            subcloud_strategy = self.get_vim_client(region).apply_strategy(
                strategy_name=self.strategy_name
            )
            if subcloud_strategy.state == vim.STATE_APPLYING:
                self.info_log(
                    strategy_step,
                    "(%s) VIM Strategy apply in progress" % self.strategy_name,
                )
            elif subcloud_strategy.state == vim.STATE_APPLIED:
                # Success.
                self.info_log(
                    strategy_step,
                    "(%s) VIM strategy has been applied" % self.strategy_name,
                )
            elif subcloud_strategy.state in [
                vim.STATE_APPLY_FAILED,
                vim.STATE_APPLY_TIMEOUT,
            ]:
                message = "VIM strategy apply failed: "
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    state=subcloud_strategy.state,
                    details=message + subcloud_strategy.apply_phase.reason,
                )
            else:
                message = "VIM strategy unexpected apply state."
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    state=subcloud_strategy.state,
                    details=message,
                )

        # wait for new strategy to apply or the existing strategy to complete.
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

            error_message = None
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise exceptions.StrategyStoppedException()
            # break out of the loop if the max number of attempts is reached
            wait_count += 1
            if wait_count >= self.wait_attempts:
                message = "Timeout applying vim strategy."
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    state=subcloud_strategy.state,
                    details=message,
                )
            # every loop we wait, even the first one
            time.sleep(self.wait_interval)

            # get the strategy
            try:
                subcloud_strategy = self.get_vim_client(region).get_strategy(
                    strategy_name=self.strategy_name, raise_error_if_missing=False
                )
                get_fail_count = 0
            except Exception:
                # When applying the strategy to a subcloud, the VIM can
                # be unreachable for a significant period of time when
                # there is a controller swact, the VIM service restarts,
                # or in the case of AIO-SX, when the controller reboots.
                get_fail_count += 1
                if get_fail_count >= self.max_failed_queries:
                    # We have waited too long.
                    message = "Timeout during recovery of VIM strategy."
                    raise exceptions.ApplyVIMStrategyFailedException(
                        subcloud=strategy_step.subcloud.name,
                        name=self.strategy_name,
                        state=subcloud_strategy.state,
                        details=message,
                    )
                self.debug_log(
                    strategy_step,
                    "Unable to get (%s) vim strategy - attempt %d"
                    % (self.strategy_name, get_fail_count),
                )
                continue
            # If an external actor has deleted the strategy, the only option
            # is to fail this state.
            if subcloud_strategy is None:
                message = "VIM Strategy no longer exists."
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    state=subcloud_strategy.state,
                    details=message,
                )

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
                # Success.
                self.info_log(
                    strategy_step,
                    "(%s) Vim strategy has been applied" % self.strategy_name,
                )
                break
            elif subcloud_strategy.state in [
                vim.STATE_APPLY_FAILED,
                vim.STATE_APPLY_TIMEOUT,
            ]:
                error_message = "VIM strategy apply failed: "
            else:
                error_message = "VIM strategy unexpected apply state."

            if error_message:
                apply_error = subcloud_strategy.apply_phase.response
                # If response is None, use the reason
                if not apply_error:
                    apply_error = subcloud_strategy.apply_phase.reason
                db_api.subcloud_update(
                    self.context,
                    strategy_step.subcloud_id,
                    error_description=apply_error,
                )
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    state=subcloud_strategy.state,
                    details=error_message + apply_error,
                )

        # Success, state machine can proceed to the next state
        return self.next_state
