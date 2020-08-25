#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.manager.states.base import BaseState


# When an unlock occurs, a reboot is triggered. During reboot, API calls fail.
# The max time allowed here is 30 minutes (ie: 30 queries with 1 minute sleep)
DEFAULT_MAX_FAILED_QUERIES = 30
DEFAULT_FAILED_SLEEP = 60

# Before and after reboot, the unlock needs to prepare for shutdown and
# do post-reboot activities during which time the API will succeed, but the
# expected states will not yet be set.
# The max time allowed here is 30 minutes (ie: 30 queries with 1 minute sleep)
DEFAULT_MAX_API_QUERIES = 30
DEFAULT_API_SLEEP = 60


class UnlockHostState(BaseState):
    """Orchestration state for unlocking a host."""

    def __init__(self, hostname='controller-0'):
        super(UnlockHostState, self).__init__(
            next_state=consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
        self.target_hostname = hostname
        self.max_api_queries = DEFAULT_MAX_API_QUERIES
        self.api_sleep_duration = DEFAULT_API_SLEEP
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def perform_state_action(self, strategy_step):
        """Unlocks a host on the subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        # Create a sysinv client on the subcloud
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name)

        host = sysinv_client.get_host(self.target_hostname)

        # if the host is already in the desired state, no need for action
        if host.administrative == consts.ADMIN_UNLOCKED:
            msg = "Host: %s already: %s." % (self.target_hostname,
                                             host.administrative)
            self.info_log(strategy_step, msg)
            return self.next_state

        # Invoke the action
        # ihost_action is 'unlock' and task is set to 'Unlocking'
        response = sysinv_client.unlock_host(host.id)
        if (response.ihost_action != 'unlock' or response.task != 'Unlocking'):
            raise Exception("Unable to unlock host %s" % self.target_hostname)

        # unlock triggers a reboot.
        # must ignore certain errors until the system completes the reboot
        # or a timeout occurs

        # Allow separate durations for failures (ie: reboot) and api retries
        api_counter = 0
        fail_counter = 0

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                # query the administrative state to see if it is the new state.
                host = self.get_sysinv_client(
                    strategy_step.subcloud.name).get_host(self.target_hostname)
                if (host.administrative == consts.ADMIN_UNLOCKED and
                        host.operational == consts.OPERATIONAL_ENABLED):
                    # Success. Break out of the loop.
                    msg = "Host: %s is now: %s %s" % (self.target_hostname,
                                                      host.administrative,
                                                      host.operational)
                    self.info_log(strategy_step, msg)
                    break
                # no exception was raised so reset fail checks
                fail_counter = 0
            except Exception:
                # Handle other exceptions due to being unreachable
                # for a significant period of time when there is a
                # controller swact, or in the case of AIO-SX,
                # when the controller reboots.
                fail_counter += 1
                if fail_counter >= self.max_failed_queries:
                    raise Exception("Timeout waiting for reboot to complete")
                time.sleep(self.failed_sleep_duration)
                # skip the api_counter
                continue
            # If the max counter is exceeeded, raise a timeout exception
            api_counter += 1
            if api_counter >= self.max_api_queries:
                raise Exception("Timeout waiting for unlock to complete")
            time.sleep(self.api_sleep_duration)

        # If we are here, the loop broke out cleanly and the action succeeded
        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
