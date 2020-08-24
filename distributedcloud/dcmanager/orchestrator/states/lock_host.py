#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState

# Max time: 10 minutes = 60 queries x 10 seconds
DEFAULT_MAX_QUERIES = 60
DEFAULT_SLEEP_DURATION = 10


class LockHostState(BaseState):
    """Orchestration state for locking a host"""

    def __init__(self, region_name, hostname='controller-0'):
        super(LockHostState, self).__init__(
            next_state=consts.STRATEGY_STATE_UPGRADING_SIMPLEX, region_name=region_name)
        self.target_hostname = hostname
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Locks a host on the subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        # Create a sysinv client on the subcloud
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name)

        host = sysinv_client.get_host(self.target_hostname)

        # if the host is already in the desired state, no need for action
        if host.administrative == consts.ADMIN_LOCKED:
            msg = "Host: %s already: %s." % (self.target_hostname,
                                             host.administrative)
            self.info_log(strategy_step, msg)
            return self.next_state

        # Invoke the action
        # ihost_action is 'lock' and task is set to 'Locking'
        response = sysinv_client.lock_host(host.id)
        if (response.ihost_action != 'lock' or response.task != 'Locking'):
            raise Exception("Unable to lock host %s" % self.target_hostname)

        # this action is asynchronous, query until it completes or times out
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            # query the administrative state to see if it is the new state.
            host = self.get_sysinv_client(
                strategy_step.subcloud.name).get_host(self.target_hostname)
            if host.administrative == consts.ADMIN_LOCKED:
                msg = "Host: %s is now: %s" % (self.target_hostname,
                                               host.administrative)
                self.info_log(strategy_step, msg)
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for lock to complete. "
                                "Please check sysinv.log on the subcloud "
                                "for details.")
            time.sleep(self.sleep_duration)

        # If we are here, the loop broke out cleanly and the action succeeded
        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
