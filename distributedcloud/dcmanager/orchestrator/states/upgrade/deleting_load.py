#
# Copyright (c) 2020-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState


# Max time: 10 minutes = 60 queries x 10 seconds between each query
DEFAULT_MAX_QUERIES = 60
DEFAULT_SLEEP_DURATION = 10


class DeletingLoadState(BaseState):
    """Upgrade state actions for deleting the N load after N+1 upgrade"""

    def __init__(self, region_name):
        super(DeletingLoadState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE, region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Delete the N load on the subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        # get the sysinv client for the subcloud
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.region_name)
        current_loads = sysinv_client.get_loads()
        load_id = None

        for load in current_loads:
            if load.state == 'imported':
                load_id = load.id
                load_version = load.software_version
                break

        if load_id:
            sysinv_client.delete_load(load_id)

            counter = 0
            while True:
                # If event handler stop has been triggered, fail the state
                if self.stopped():
                    raise StrategyStoppedException()

                # Get a sysinv client each time. It will automatically renew the
                # token if it is about to expire.
                sysinv_client = self.get_sysinv_client(strategy_step.subcloud.region_name)
                if len(sysinv_client.get_loads()) == 1:
                    msg = "Load %s deleted." % load_version
                    self.info_log(strategy_step, msg)
                    break

                counter += 1
                if counter >= self.max_queries:
                    raise Exception("Timeout waiting for load delete to complete")
                time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
