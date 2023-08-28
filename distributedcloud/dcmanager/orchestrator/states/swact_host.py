#
# Copyright (c) 2020-2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState

# When a swact occurs, services become unavailable and API calls may fail.
# The max time allowed here is 30 minutes (ie: 180 queries with 10 secs sleep)
DEFAULT_MAX_FAILED_QUERIES = 120
DEFAULT_FAILED_SLEEP = 10

# Max time: 10 minutes = 60 queries x 10 seconds
DEFAULT_MAX_QUERIES = 60
DEFAULT_SLEEP_DURATION = 10

# After a swact, there is a sleep before proceeding to the next state
# Added another minute to ensure controller is stable
DEFAULT_SWACT_SLEEP = 180


class SwactHostState(BaseState):
    """Orchestration state for host swact"""

    def __init__(self, next_state, region_name, active, standby):
        super(SwactHostState, self).__init__(
            next_state=next_state, region_name=region_name)
        self.active = active
        self.standby = standby
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def perform_state_action(self, strategy_step):
        """Swact host on the subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        region = self.get_region_name(strategy_step)

        active_host = self.get_sysinv_client(region).get_host(self.active)
        standby_host = self.get_sysinv_client(region).get_host(self.standby)

        # if the desired active host is already the Active Controller, no need for
        # action
        if active_host.capabilities.get('Personality') == \
                consts.PERSONALITY_CONTROLLER_ACTIVE:
            msg = "Host: %s already the active controller." % (self.active)
            self.info_log(strategy_step, msg)
            return self.next_state

        # Perform swact action
        response = self.get_sysinv_client(region).swact_host(standby_host.id)
        if response.task != 'Swacting':
            raise Exception("Unable to swact to host %s" % self.active)

        # Allow separate durations for failures and api retries
        fail_counter = 0
        api_counter = 0

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                # query the administrative state to see if it is the new state.
                host = self.get_sysinv_client(region).get_host(self.active)
                if host.capabilities.get('Personality') == \
                        consts.PERSONALITY_CONTROLLER_ACTIVE:
                    msg = "Host: %s is now the active controller." % (self.active)
                    self.info_log(strategy_step, msg)
                    break
                fail_counter = 0
            except Exception:
                # Handle other exceptions due to being unreachable
                # for a significant period of time when there is a
                # controller swact
                fail_counter += 1
                if fail_counter >= self.max_failed_queries:
                    raise Exception("Timeout waiting for swact to complete")
                time.sleep(self.failed_sleep_duration)
                # skip the api_counter
                continue
            api_counter += 1
            if api_counter >= self.max_queries:
                raise Exception("Timeout waiting for swact to complete. "
                                "Please check sysinv.log on the subcloud "
                                "for details.")
            time.sleep(self.sleep_duration)

        # If we are here, the loop broke out cleanly and the action succeeded
        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        # Adding a 3 minute delay (DEFAULT_SWACT_SLEEP) before moving to the
        # next state
        self.info_log(strategy_step,
                      "Waiting %s seconds before proceeding"
                      % DEFAULT_SWACT_SLEEP)
        time.sleep(DEFAULT_SWACT_SLEEP)
        return self.next_state
