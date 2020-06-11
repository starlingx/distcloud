#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.manager.states.base import BaseState

ALREADY_ACTIVATING_STATES = ['activation-requested',
                             'activation-failed',
                             'activation-complete',
                             'activating']

ACTIVATING_COMPLETED_STATES = ['activation-failed',
                               'activation-complete',
                               'aborting']

# Max time: 10 minutes = 60 queries x 10 seconds sleep between queries
DEFAULT_MAX_QUERIES = 60
DEFAULT_SLEEP_DURATION = 10


class ActivatingUpgradeState(BaseState):
    """Upgrade state actions for activating an upgrade"""

    def __init__(self):
        super(ActivatingUpgradeState, self).__init__()
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def get_upgrade_state(self, sysinv_client):
        upgrades = sysinv_client.get_upgrades()
        if len(upgrades) == 0:
            raise Exception("No upgrades were found to activate")

        # The list of upgrades will never contain more than one entry.
        return upgrades[0].state

    def perform_state_action(self, strategy_step):
        """Activate an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """
        # get the keystone and sysinv clients for the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        upgrade_state = self.get_upgrade_state(sysinv_client)

        # Check if an existing upgrade is already activated
        if upgrade_state in ALREADY_ACTIVATING_STATES:
            self.info_log(strategy_step,
                          "Already in an activating state:%s" % upgrade_state)
            return True

        # invoke the API 'upgrade-activate'.
        # Throws an exception on failure (no upgrade found, bad host state)
        sysinv_client.upgrade_activate()
        # Need to loop until changed to a activating completed state
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            upgrade_state = self.get_upgrade_state(sysinv_client)
            if upgrade_state in ACTIVATING_COMPLETED_STATES:
                self.info_log(strategy_step,
                              "Activation completed. State=%s" % upgrade_state)
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for activation to complete")
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
