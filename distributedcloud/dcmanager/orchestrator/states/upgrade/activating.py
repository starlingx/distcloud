#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState

ACTIVATING_COMPLETED_STATES = ['activation-complete',
                               'aborting']

ACTIVATING_RETRY_STATES = ['activation-failed', ]

ACTIVATING_IN_PROGRESS_STATES = ['activating', 'activating-hosts', ]

# Max time: 60 minutes = 60 queries x 60 seconds sleep between queries
DEFAULT_MAX_QUERIES = 60
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
        try:
            upgrades = self.get_sysinv_client(
                strategy_step.subcloud.region_name).get_upgrades()

        except Exception as exception:
            self.warn_log(strategy_step,
                          "Encountered exception: %s, "
                          "retry upgrade activation for subcloud %s."
                          % (str(exception), strategy_step.subcloud.name))
            return ACTIVATING_RETRY_STATES[0]

        if len(upgrades) == 0:
            raise Exception("No upgrades were found to activate")

        # The list of upgrades will never contain more than one entry.
        return upgrades[0].state

    def perform_state_action(self, strategy_step):
        """Activate an upgrade on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        try:
            upgrade_state = self.get_upgrade_state(strategy_step)
        except Exception as ex:
            self.info_log(strategy_step, "%s for %s."
                          % (str(ex), strategy_step.subcloud.name))
            return self.next_state

        # Check if an existing upgrade is already activated
        if upgrade_state in ACTIVATING_COMPLETED_STATES:
            self.info_log(strategy_step,
                          "Already in an activating state:%s" % upgrade_state)
            return self.next_state

        # Need to loop
        # - attempt an initial activate one or more times
        # - loop until state changed to a activating completed state
        # - re-attempt activate if activation fails
        audit_counter = 0
        activate_retry_counter = 0
        first_activate = True
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()

            # if max retries have occurred, fail the state
            if activate_retry_counter >= self.max_failed_retries:
                error_msg = utils.get_failure_msg(strategy_step.subcloud.region_name)
                db_api.subcloud_update(
                    self.context, strategy_step.subcloud_id,
                    error_description=error_msg[0:consts.ERROR_DESCRIPTION_LENGTH])
                details = ("Failed to activate upgrade. Please check "
                           "sysinv.log on the subcloud or "
                           "%s on central for details." %
                           (consts.ERROR_DESC_CMD))
                raise Exception(details)

            # We may need multiple attempts to issue the first activate
            # if keystone is down, impacting the ability to send the activate
            if first_activate:
                # invoke the API 'upgrade-activate'.
                # Normally only auth failures deserve retry
                # (no upgrade found, bad host state, auth)
                try:
                    self.get_sysinv_client(
                        strategy_step.subcloud.region_name).upgrade_activate()
                    first_activate = False  # clear first activation flag
                    activate_retry_counter = 0  # reset activation retries
                except Exception as exception:
                    # increment the retry counter on failure
                    activate_retry_counter += 1
                    self.warn_log(strategy_step,
                                  "Encountered exception: %s, "
                                  "retry upgrade activation for subcloud %s."
                                  % (str(exception),
                                     strategy_step.subcloud.name))
                    # cannot flow into the remaining code. sleep  / continue
                    time.sleep(self.sleep_duration)
                    continue

            upgrade_state = self.get_upgrade_state(strategy_step)
            if upgrade_state in ACTIVATING_RETRY_STATES:
                # We failed.  Better try again
                activate_retry_counter += 1
                self.info_log(strategy_step,
                              "Activation failed, retrying... State=%s"
                              % upgrade_state)
                try:
                    self.get_sysinv_client(
                        strategy_step.subcloud.region_name).upgrade_activate()
                except Exception as exception:
                    self.warn_log(strategy_step,
                                  "Encountered exception: %s, "
                                  "retry upgrade activation for subcloud %s."
                                  % (str(exception),
                                     strategy_step.subcloud.name))
            elif upgrade_state in ACTIVATING_IN_PROGRESS_STATES:
                self.info_log(strategy_step,
                              "Activation in progress, waiting... State=%s"
                              % upgrade_state)
            elif upgrade_state in ACTIVATING_COMPLETED_STATES:
                self.info_log(strategy_step,
                              "Activation completed. State=%s"
                              % upgrade_state)
                break
            audit_counter += 1
            if audit_counter >= self.max_queries:
                error_msg = utils.get_failure_msg(strategy_step.subcloud.region_name)
                db_api.subcloud_update(
                    self.context, strategy_step.subcloud_id,
                    error_description=error_msg[0:consts.ERROR_DESCRIPTION_LENGTH])
                details = ("Timeout waiting for activation to complete. "
                           "Please check sysinv.log on the subcloud or "
                           "%s on central for details." %
                           (consts.ERROR_DESC_CMD))
                raise Exception(details)
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
