#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.orchestrator.states.base import BaseState

# When an unlock occurs, a reboot is triggered. During reboot, API calls fail.
# The max time allowed here is 30 minutes (ie: 180 queries with 10 secs sleep)
DEFAULT_MAX_FAILED_QUERIES = 180
DEFAULT_FAILED_SLEEP = 10

# Max time: 30 minutes = 180 queries x 10 seconds
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10


class UpgradingDuplexState(BaseState):
    """Update state for upgrading a non-simplex subcloud host"""

    def __init__(self, region_name):
        super(UpgradingDuplexState, self).__init__(
            next_state=consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1, region_name=region_name)
        self.target_hostname = "controller-1"
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def perform_state_action(self, strategy_step):
        """Upgrade a duplex host on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        self.info_log(strategy_step, "Performing duplex upgrade for subcloud")
        region = self.get_region_name(strategy_step)
        host = self.get_sysinv_client(
            region).get_host(self.target_hostname)
        self.get_sysinv_client(region).upgrade_host(host.id)

        # Wait for controller-1 to reinstall with the load N+1
        # and become locked-disabled-online state.
        # this action is asynchronous, query until it completes or times out

        # Allow separate durations for failures (ie: reboot) and api retries
        fail_counter = 0
        api_counter = 0

        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                upgrades = self.get_sysinv_client(region).get_upgrades()

                if len(upgrades) != 0:
                    if (upgrades[0].state == consts.UPGRADE_STATE_DATA_MIGRATION_FAILED or
                            upgrades[0].state == consts.UPGRADE_STATE_DATA_MIGRATION_COMPLETE):
                        msg = "Upgrade state is %s now" % (upgrades[0].state)
                        self.info_log(strategy_step, msg)
                        break
                fail_counter = 0
            except Exception:
                # Handle other exceptions due to being unreachable
                # for a significant period of time when there is a
                # controller swact
                fail_counter += 1
                if fail_counter >= self.max_failed_queries:
                    raise Exception("Timeout waiting for reboot to complete")
                time.sleep(self.failed_sleep_duration)
                # skip the api_counter
                continue
            api_counter += 1
            if api_counter >= self.max_queries:
                raise Exception("Timeout waiting for update state to be updated to "
                                "updated to 'data-migration-failed' or 'data-migration-complete'."
                                "Please check sysinv.log on the subcloud "
                                "for details.")
            time.sleep(self.sleep_duration)

        # If the upgrade state is 'data-migration-complete' we move to the
        # next state, else if it is 'data-migration-failed' we go to the failed
        # state.
        upgrades = self.get_sysinv_client(region).get_upgrades()

        if len(upgrades) == 0:
            raise Exception("No upgrades were found")

        # The list of upgrades will never contain more than one entry.
        if upgrades[0].state == 'data-migration-failed':
            raise Exception("Data migration failed on host %s" % self.target_hostname)

        # If we reach at this point, the upgrade state is 'data-migration-complete'
        # and we can move to the next state.
        return self.next_state
