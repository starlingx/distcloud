#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common.consts import ADMIN_UNLOCKED
from dcmanager.common.consts import OPERATIONAL_ENABLED
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
        super(UnlockHostState, self).__init__()
        self.target_hostname = hostname
        self.max_api_queries = DEFAULT_MAX_API_QUERIES
        self.api_sleep_duration = DEFAULT_API_SLEEP
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def perform_state_action(self, strategy_step):
        """Unlocks a host on the subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """

        # Create a sysinv client on the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        host = sysinv_client.get_host(self.target_hostname)

        # if the host is already in the desired state, no need for action
        if host.administrative == ADMIN_UNLOCKED:
            msg = "Host: %s already: %s." % (self.target_hostname,
                                             host.administrative)
            self.info_log(strategy_step, msg)
            return True

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
        # Allow just one failed auth (token expired)
        auth_failure = False

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                # query the administrative state to see if it is the new state.
                host = sysinv_client.get_host(self.target_hostname)
                if (host.administrative == ADMIN_UNLOCKED and
                        host.operational == OPERATIONAL_ENABLED):
                    # Success. Break out of the loop.
                    msg = "Host: %s is now: %s %s" % (self.target_hostname,
                                                      host.administrative,
                                                      host.operational)
                    self.info_log(strategy_step, msg)
                    break
                # no exception was raised so reset fail and auth checks
                auth_failure = False
                fail_counter = 0
            except Exception as e:
                if e.message == "Authorization failed":
                    # Since a token could expire while waiting, generate
                    # a new token (by re-creating the client) and re-try the
                    # request, but only once.
                    if not auth_failure:
                        auth_failure = True
                        self.info_log(strategy_step,
                                      "Authorization failure. Retrying...")
                        ks_client = self.get_keystone_client(
                            strategy_step.subcloud.name)
                        sysinv_client = self.get_sysinv_client(
                            strategy_step.subcloud.name,
                            ks_client.session)
                        continue
                    else:
                        raise Exception("Repeated authorization failures.")
                else:
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
        return True
