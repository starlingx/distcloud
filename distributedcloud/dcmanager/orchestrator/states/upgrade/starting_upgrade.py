#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import time

from dccommon.drivers.openstack.vim import ALARM_RESTRICTIONS_RELAXED
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState

DEFAULT_FORCE_FLAG = False
# Max time 30 minutes = 180 attempts, with 10 seconds between
DEFAULT_MAX_QUERIES = 180
DEFAULT_SLEEP_DURATION = 10
MAX_FAILED_RETRIES = 10
UPGRADE_FAILED = 'upgrade-failed'
UPGRADE_STARTED_STATES = ['started', ]
UPGRADE_RETRY_STATES = [UPGRADE_FAILED, ]


class StartingUpgradeState(BaseState):
    """Upgrade state for starting an upgrade on a subcloud"""

    def __init__(self, region_name):
        super(StartingUpgradeState, self).__init__(
            next_state=consts.STRATEGY_STATE_TRANSFERRING_CA_CERTIFICATE,
            region_name=region_name)
        self.sleep_duration = DEFAULT_SLEEP_DURATION
        self.max_queries = DEFAULT_MAX_QUERIES
        self.max_failed_retries = MAX_FAILED_RETRIES

    def get_upgrade_state(self, strategy_step):
        try:
            upgrades = self.get_sysinv_client(
                strategy_step.subcloud.name).get_upgrades()
        except Exception as exception:
            self.warn_log(strategy_step,
                          "Encountered exception: %s, "
                          "retry upgrade start for subcloud %s."
                          % (str(exception), strategy_step.subcloud.name))
            return UPGRADE_FAILED
        if len(upgrades) == 0:
            raise Exception("Failed to generate upgrade data. Please "
                            "check sysinv.log on the subcloud for details.")
        # The list of upgrades will never contain more than one entry.
        return upgrades[0].state

    def perform_state_action(self, strategy_step):
        """Start an upgrade on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        # Check if an existing upgrade is already in progress.
        # The list of upgrades will never contain more than one entry.
        upgrades = self.get_sysinv_client(
            strategy_step.subcloud.name).get_upgrades()
        if upgrades is not None and len(upgrades) > 0:
            for upgrade in upgrades:
                # If a previous upgrade exists (even one that failed) skip
                self.info_log(strategy_step,
                              "An upgrade already exists: %s" % upgrade)
                return self.next_state
        else:
            # invoke the API 'upgrade-start'.
            # query the alarm_restriction_type from DB SwUpdateOpts
            force_flag = DEFAULT_FORCE_FLAG
            opts_dict = \
                utils.get_sw_update_opts(self.context,
                                         for_sw_update=True,
                                         subcloud_id=strategy_step.subcloud_id)
            if opts_dict is not None:
                force_flag = (opts_dict.get('alarm-restriction-type')
                              == ALARM_RESTRICTIONS_RELAXED)

            # This call is asynchronous and throws an exception on failure.
            self.get_sysinv_client(
                strategy_step.subcloud.name).upgrade_start(force=force_flag)

        # Do not move to the next state until the upgrade state is correct
        counter = 0
        retry_counter = 0
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            upgrade_state = self.get_upgrade_state(strategy_step)
            if upgrade_state in UPGRADE_STARTED_STATES:
                self.info_log(strategy_step,
                              "Upgrade started. State=%s" % upgrade_state)
                break
            if upgrade_state in UPGRADE_RETRY_STATES:
                retry_counter += 1
                if retry_counter >= self.max_failed_retries:
                    raise Exception("Failed to start upgrade. Please "
                                    "check sysinv.log on the subcloud for "
                                    "details.")
                self.warn_log(strategy_step,
                              "Upgrade start failed, retrying... State=%s"
                              % upgrade_state)
                try:
                    self.get_sysinv_client(
                        strategy_step.subcloud.name).upgrade_start(force=force_flag)
                except Exception as exception:
                    self.warn_log(strategy_step,
                                  "Encountered exception: %s, "
                                  "during upgrade start for subcloud %s."
                                  % (str(exception),
                                     strategy_step.subcloud.name))
            counter += 1
            if counter >= self.max_queries:
                raise Exception("Timeout waiting for upgrade to start")
            time.sleep(self.sleep_duration)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return self.next_state
