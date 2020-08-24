#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.db import api as db_api
from dcmanager.manager.states.base import BaseState


# Max time: 10 minutes = 60 queries x 10 seconds between each query
DEFAULT_MAX_QUERIES = 60
DEFAULT_SLEEP_DURATION = 10


class CompletingUpgradeState(BaseState):
    """Upgrade state actions for completing an upgrade"""

    def __init__(self, region_name):
        super(CompletingUpgradeState, self).__init__(
            next_state=consts.STRATEGY_STATE_DELETING_LOAD, region_name=region_name)
        # max time to wait (in seconds) is: sleep_duration * max_queries
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES

    def finalize_upgrade(self, strategy_step):
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name)

        software_version = sysinv_client.get_system().software_version

        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            software_version=software_version)
        return self.next_state

    def perform_state_action(self, strategy_step):
        """Complete an upgrade on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        # get the sysinv client for the subcloud
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name)

        # upgrade-complete causes the upgrade to be deleted.
        # if no upgrade exists, there is no need to call it.
        # The API should always return a list
        upgrades = sysinv_client.get_upgrades()
        if len(upgrades) == 0:
            self.info_log(strategy_step,
                          "No upgrades exist. Nothing needs completing")
            return self.finalize_upgrade(strategy_step)

        # invoke the API 'upgrade-complete'
        # This is a partially blocking call that raises exception on failure.
        sysinv_client.upgrade_complete()

        # 'completion' deletes the upgrade. Need to loop until it is deleted
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()

            upgrades = self.get_sysinv_client(
                strategy_step.subcloud.name).get_upgrades()
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
        return self.finalize_upgrade(strategy_step)
