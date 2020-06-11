#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.manager.states.base import BaseState

# Max time: 10 minutes = 60 queries x 10 seconds between each query
DEFAULT_MAX_QUERIES = 60
DEFAULT_SLEEP_DURATION = 10


class CompletingUpgradeState(BaseState):
    """Upgrade state actions for completing an upgrade"""

    def __init__(self):
        super(CompletingUpgradeState, self).__init__()
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def perform_state_action(self, strategy_step):
        """Complete an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """
        # get the keystone and sysinv clients for the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        # upgrade-complete causes the upgrade to be deleted.
        # if no upgrade exists, there is no need to call it.
        # The API should always return a list
        upgrades = sysinv_client.get_upgrades()
        if len(upgrades) == 0:
            self.info_log(strategy_step,
                          "No upgrades exist. Nothing needs completing")
            return True

        # invoke the API 'upgrade-complete'
        # This is a partially blocking call that raises exception on failure.
        sysinv_client.upgrade_complete()

        # 'completion' deletes the upgrade. Need to loop until it is deleted
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            upgrades = sysinv_client.get_upgrades()
            if len(upgrades) == 0:
                self.info_log(strategy_step,
                              "Upgrade completed.")
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for completion to complete")
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
