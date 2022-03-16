#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import retrying
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState


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

    @retrying.retry(stop_max_attempt_number=consts.PLATFORM_RETRY_MAX_ATTEMPTS,
                    wait_fixed=consts.PLATFORM_RETRY_SLEEP_MILLIS)
    def _get_software_version(self, strategy_step):
        """Internal utility method to query software version from a subcloud

        This method is 'retry' wrapped to attempt multiple times with a
        small wait period between attempts if any exception is raised
        """
        region = self.get_region_name(strategy_step)
        return self.get_sysinv_client(region).get_system().software_version

    @retrying.retry(stop_max_attempt_number=consts.PLATFORM_RETRY_MAX_ATTEMPTS,
                    wait_fixed=consts.PLATFORM_RETRY_SLEEP_MILLIS)
    def _get_upgrades(self, strategy_step):
        """Internal utility method to query a subcloud for its upgrades

        This method is 'retry' wrapped to attempt multiple times with a
        small wait period between attempts if any exception is raised
        """
        region = self.get_region_name(strategy_step)
        return self.get_sysinv_client(region).get_upgrades()

    @retrying.retry(stop_max_attempt_number=consts.PLATFORM_RETRY_MAX_ATTEMPTS,
                    wait_fixed=consts.PLATFORM_RETRY_SLEEP_MILLIS)
    def _upgrade_complete(self, strategy_step):
        """Internal utility method to complete an upgrade in a subcloud

        This method is 'retry' wrapped to attempt multiple times with a
        small wait period between attempts if any exception is raised

        returns None
        """
        region = self.get_region_name(strategy_step)
        return self.get_sysinv_client(region).upgrade_complete()

    def finalize_upgrade(self, strategy_step):
        software_version = self._get_software_version(strategy_step)

        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            software_version=software_version)
        return self.next_state

    # todo(abailey): determine if service restarts can be made predictable
    # todo(abailey): other states should have similar retry decorators and
    # this may also be reasonable to add within the client API calls.
    def perform_state_action(self, strategy_step):
        """Complete an upgrade on a subcloud

        We should never cache the client. re-query it.
        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.

        This state runs during a time when manifests are applying and services
        are restarting, and therefore any API call in this method can randomly
        fail.  To accomodate this, every call is wrapped with retries.
        """

        # upgrade-complete causes the upgrade to be deleted.
        # if no upgrade exists, there is no need to call it.
        # The API should always return a list
        upgrades = self._get_upgrades(strategy_step)
        if len(upgrades) == 0:
            self.info_log(strategy_step,
                          "No upgrades exist. Nothing needs completing")
            return self.finalize_upgrade(strategy_step)
        # invoke the API 'upgrade-complete'
        # This is a partially blocking call that raises exception on failure.
        # We will re-attempt even if that failure is encountered
        self._upgrade_complete(strategy_step)

        # 'completion' deletes the upgrade. Need to loop until it is deleted
        counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()

            upgrades = self._get_upgrades(strategy_step)
            if len(upgrades) == 0:
                self.info_log(strategy_step, "Upgrade completed.")
                break
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for completion to complete")
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.finalize_upgrade(strategy_step)
