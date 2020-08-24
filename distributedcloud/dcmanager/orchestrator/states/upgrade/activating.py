#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState


ACTIVATING_COMPLETED_STATES = ['activation-complete',
                               'aborting']

ACTIVATING_RETRY_STATES = ['activation-failed', ]

ACTIVATING_IN_PROGRESS_STATES = ['activating', ]

# Max time: 45 minutes = 45 queries x 60 seconds sleep between queries
DEFAULT_MAX_QUERIES = 45
DEFAULT_SLEEP_DURATION = 60
MAX_FAILED_RETRIES = 10


class ActivatingUpgradeState(BaseState):
    """Upgrade state actions for activating an upgrade"""

    def __init__(self, region_name):
        super(ActivatingUpgradeState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETING_UPGRADE, region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES
        self.max_failed_retries = MAX_FAILED_RETRIES

    def get_upgrade_state(self, strategy_step):
        upgrades = self.get_sysinv_client(
            strategy_step.subcloud.name).get_upgrades()

        if len(upgrades) == 0:
            raise Exception("No upgrades were found to activate")

        # The list of upgrades will never contain more than one entry.
        return upgrades[0].state

    def perform_state_action(self, strategy_step):
        """Activate an upgrade on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        upgrade_state = self.get_upgrade_state(strategy_step)

        # Check if an existing upgrade is already activated
        if upgrade_state in ACTIVATING_COMPLETED_STATES:
            self.info_log(strategy_step,
                          "Already in an activating state:%s" % upgrade_state)
            return self.next_state

        # invoke the API 'upgrade-activate'.
        # Throws an exception on failure (no upgrade found, bad host state)
        self.get_sysinv_client(strategy_step.subcloud.name).upgrade_activate()
        # Need to loop until changed to a activating completed state
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            upgrade_state = self.get_upgrade_state(strategy_step)

            if upgrade_state in ACTIVATING_RETRY_STATES:
                if counter >= self.max_failed_retries:
                    raise Exception("Failed to activate upgrade. Please "
                                    "check sysinv.log on the subcloud for "
                                    "details.")
                # We failed.  Better try again
                self.info_log(strategy_step,
                              "Activation failed, retrying... State=%s"
                              % upgrade_state)
                self.get_sysinv_client(
                    strategy_step.subcloud.name).upgrade_activate()
            elif upgrade_state in ACTIVATING_IN_PROGRESS_STATES:
                self.info_log(strategy_step,
                              "Activation in progress, waiting... State=%s"
                              % upgrade_state)
            elif upgrade_state in ACTIVATING_COMPLETED_STATES:
                self.info_log(strategy_step,
                              "Activation completed. State=%s"
                              % upgrade_state)
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for activation to complete. "
                                "Please check sysinv.log on the subcloud for "
                                "details.")
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
