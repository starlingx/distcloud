#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from oslo_log import log as logging

from dcmanager.common.consts import ADMIN_UNLOCKED
from dcmanager.manager.states.base import BaseState

LOG = logging.getLogger(__name__)
DEFAULT_MAX_QUERIES = 6
DEFAULT_SLEEP_DURATION = 10


class UnlockHostState(BaseState):
    """Orchestration state for unlocking a host"""

    def __init__(self,
                 hostname='controller-0',
                 max_queries=DEFAULT_MAX_QUERIES,
                 sleep_duration=DEFAULT_SLEEP_DURATION):
        super(UnlockHostState, self).__init__()
        self.target_hostname = hostname
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = sleep_duration
        self.max_queries = max_queries

    def check_async_counter(self, counter):
        if counter >= self.max_queries:
            raise Exception("Timeout waiting for unlock to complete")
        time.sleep(self.sleep_duration)

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
            self.debug_log(strategy_step, msg)
            return True

        # Invoke the action
        # ihost_action is 'unlock' and task is set to 'Unlocking'
        response = sysinv_client.unlock_host(host.id)
        if (response.ihost_action != 'unlock' or response.task != 'Unlocking'):
            raise Exception("Unable to unlock host %s" % self.target_hostname)

        # this action is asynchronous, query until it completes or times out
        async_counter = 0
        while True:
            # query the administrative state to see if it is the new state.
            host = sysinv_client.get_host(self.target_hostname)
            if host.administrative == ADMIN_UNLOCKED:
                msg = "Host: %s is now: %s" % (self.target_hostname,
                                               host.administrative)
                self.debug_log(strategy_step, msg)
                break
            async_counter += 1
            # check_async_counter throws exception if loops exceeded or aborted
            self.check_async_counter(async_counter)

        # If we are here, the loop broke out cleanly and the action succeeded
        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
