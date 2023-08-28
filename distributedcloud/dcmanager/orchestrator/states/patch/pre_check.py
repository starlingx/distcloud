#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.states.base import BaseState

IGNORED_ALARMS_IDS = ("900.001",)  # Patch in progress


class PreCheckState(BaseState):
    """Pre check patch orchestration state"""

    def __init__(self, region_name):
        super(PreCheckState, self).__init__(
            next_state=consts.STRATEGY_STATE_UPDATING_PATCHES,
            region_name=region_name)

    def has_mgmt_affecting_alarms(self, ignored_alarms=()):
        alarms = self.get_fm_client(self.region_name).get_alarms()
        for alarm in alarms:
            if alarm.mgmt_affecting == "True" and \
                    alarm.alarm_id not in ignored_alarms:
                return True
        # No management affecting alarms
        return False

    def perform_state_action(self, strategy_step):
        """Pre check region status"""
        self.info_log(strategy_step, "Checking subcloud alarm status")

        # Stop patching if the subcloud contains management affecting alarms.
        message = None
        try:
            if self.has_mgmt_affecting_alarms(ignored_alarms=IGNORED_ALARMS_IDS):
                message = ("Subcloud contains one or more management affecting"
                           " alarm(s). It will not be patched. Please resolve"
                           " the alarm condition(s) and try again.")
        except Exception as e:
            self.exception_log(strategy_step,
                               "Failed to obtain subcloud alarm report")
            message = ("Failed to obtain subcloud alarm report due to: (%s)."
                       " Please see /var/log/dcmanager/orchestrator.log for"
                       " details" % str(e))

        if message:
            raise Exception(message)

        return self.next_state
