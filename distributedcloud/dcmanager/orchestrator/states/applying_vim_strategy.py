#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dccommon.drivers.openstack import vim
from dccommon import exceptions as vim_exc
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

    def _get_vim_strategy(self, vim_client, region, strategy_step):
        """Get the initial VIM strategy, raising an exception if necessary."""
        try:
            subcloud_strategy = vim_client.get_strategy(
                strategy_name=self.strategy_name, raise_error_if_missing=False
            )
        except vim_exc.VIMClientException as e:
            raise exceptions.ApplyVIMStrategyFailedException(
                subcloud=strategy_step.subcloud.name,
                name=self.strategy_name,
                details=f"Failed to get VIM strategy: {str(e)}",
            )
        return subcloud_strategy

    def _apply_vim_strategy(self, vim_client, region, strategy_step):
        """Attempt to apply the VIM strategy and handle exceptions."""
        try:
            subcloud_strategy = vim_client.apply_strategy(
                strategy_name=self.strategy_name
            )
        except vim_exc.VIMClientException as e:
            raise exceptions.ApplyVIMStrategyFailedException(
                subcloud=strategy_step.subcloud.name,
                name=self.strategy_name,
                details=f"Failed to apply VIM strategy: {str(e)}",
            )

        if subcloud_strategy.state == vim.STATE_APPLYING:
            self.info_log(
                strategy_step, f"({self.strategy_name}) VIM Strategy apply in progress"
            )
        elif subcloud_strategy.state == vim.STATE_APPLIED:
            self.info_log(
                strategy_step, f"({self.strategy_name}) VIM strategy has been applied"
            )
        else:
            self._handle_apply_failure(strategy_step, subcloud_strategy)

    def _handle_apply_failure(self, strategy_step, subcloud_strategy):
        """Handle cases where applying the VIM strategy fails."""
        apply_error = (
            subcloud_strategy.apply_phase.response
            or subcloud_strategy.apply_phase.reason
        )
        db_api.subcloud_update(
            self.context,
            strategy_step.subcloud_id,
            error_description=apply_error,
        )
        if subcloud_strategy.state in [vim.STATE_APPLY_FAILED, vim.STATE_APPLY_TIMEOUT]:
            raise exceptions.ApplyVIMStrategyFailedException(
                subcloud=strategy_step.subcloud.name,
                name=self.strategy_name,
                state=subcloud_strategy.state,
                details=f"VIM strategy apply failed: {apply_error}",
            )
        raise exceptions.ApplyVIMStrategyFailedException(
            subcloud=strategy_step.subcloud.name,
            name=self.strategy_name,
            state=subcloud_strategy.state,
            details="VIM strategy unexpected apply state.",
        )

    def _wait_for_strategy_apply(
        self, vim_client, region, strategy_step, subcloud_strategy
    ):
        """Monitor the progress of the VIM strategy application."""
        wait_count = 0
        get_fail_count = 0
        last_details = ""

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise exceptions.StrategyStoppedException()
            # break out of the loop if the max number of attempts is reached
            wait_count += 1
            if wait_count >= self.wait_attempts:
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    details="Timeout applying vim strategy.",
                )
            # every loop we wait, even the first one
            time.sleep(self.wait_interval)
            # get the strategy
            try:
                subcloud_strategy = vim_client.get_strategy(
                    strategy_name=self.strategy_name, raise_error_if_missing=False
                )
                get_fail_count = 0
            except vim_exc.VIMClientException as e:
                # When applying the strategy to a subcloud, the VIM can
                # be unreachable for a significant period of time when
                # there is a controller swact, the VIM service restarts,
                # or in the case of AIO-SX, when the controller reboots.
                get_fail_count += 1
                self.info_log(
                    strategy_step,
                    (
                        f"Unable to get ({self.strategy_name}) vim strategy - "
                        f"attempt {get_fail_count} of {self.max_failed_queries}."
                    ),
                )
                if get_fail_count >= self.max_failed_queries:
                    raise exceptions.ApplyVIMStrategyFailedException(
                        subcloud=strategy_step.subcloud.name,
                        name=self.strategy_name,
                        state=subcloud_strategy.state,
                        details=(
                            f"Timeout during recovery of VIM strategy. "
                            f"Details: {str(e)}"
                        ),
                    )
                continue

            if subcloud_strategy is None:
                raise exceptions.ApplyVIMStrategyFailedException(
                    subcloud=strategy_step.subcloud.name,
                    name=self.strategy_name,
                    details="VIM Strategy no longer exists.",
                )

            if subcloud_strategy.state == vim.STATE_APPLYING:
                self._log_apply_progress(strategy_step, subcloud_strategy, last_details)
            elif subcloud_strategy.state == vim.STATE_APPLIED:
                self.info_log(
                    strategy_step,
                    f"({self.strategy_name}) Vim strategy has been applied",
                )
                break
            else:
                self._handle_apply_failure(strategy_step, subcloud_strategy)

    def _log_apply_progress(self, strategy_step, subcloud_strategy, last_details):
        """Log the progress of the VIM strategy application."""
        new_details = (
            f"{subcloud_strategy.current_phase} phase is "
            f"{subcloud_strategy.current_phase_completion_percentage}% complete"
        )
        if new_details != last_details:
            self.info_log(strategy_step, new_details)
            last_details = new_details
            db_api.strategy_step_update(
                self.context, strategy_step.subcloud_id, details=new_details
            )

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

        try:
            vim_client = self.get_vim_client(region)
        except Exception as e:
            raise exceptions.ApplyVIMStrategyFailedException(
                subcloud=strategy_step.subcloud.name,
                name=self.strategy_name,
                details=f"Failed to get VIM client: {str(e)}",
            )
        subcloud_strategy = self._get_vim_strategy(vim_client, region, strategy_step)

        # We have a VIM strategy, but need to check if it is ready to apply
        if subcloud_strategy.state == vim.STATE_READY_TO_APPLY:
            self._apply_vim_strategy(vim_client, region, strategy_step)

        # wait for new strategy to apply or the existing strategy to complete.
        # Loop until the strategy applies. Repeatedly query the API
        # This can take a long time.
        # Waits for up to 60 minutes for the current phase or completion
        # percentage to change before giving up.
        self._wait_for_strategy_apply(
            vim_client, region, strategy_step, subcloud_strategy
        )

        return self.next_state
