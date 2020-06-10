#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common.consts import ADMIN_LOCKED
from dcmanager.manager.states.base import BaseState

DEFAULT_MAX_QUERIES = 6
DEFAULT_SLEEP_DURATION = 10


class LockHostState(BaseState):
    """Orchestration state for locking a host"""

    def __init__(self,
                 hostname='controller-0'):
        super(LockHostState, self).__init__()
        self.target_hostname = hostname
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Locks a host on the subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """

        # Create a sysinv client on the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        host = sysinv_client.get_host(self.target_hostname)

        # if the host is already in the desired state, no need for action
        if host.administrative == ADMIN_LOCKED:
            msg = "Host: %s already: %s." % (self.target_hostname,
                                             host.administrative)
            self.info_log(strategy_step, msg)
            return True

        # Invoke the action
        # ihost_action is 'lock' and task is set to 'Locking'
        response = sysinv_client.lock_host(host.id)
        if (response.ihost_action != 'lock' or response.task != 'Locking'):
            raise Exception("Unable to lock host %s" % self.target_hostname)

        # this action is asynchronous, query until it completes or times out
        counter = 0
        while True:
            # query the administrative state to see if it is the new state.
            host = sysinv_client.get_host(self.target_hostname)
            if host.administrative == ADMIN_LOCKED:
                msg = "Host: %s is now: %s" % (self.target_hostname,
                                               host.administrative)
                self.info_log(strategy_step, msg)
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for lock to complete")
            time.sleep(self.sleep_duration)
            # todo(abailey): add support for checking if the thread is stopped

        # If we are here, the loop broke out cleanly and the action succeeded
        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
