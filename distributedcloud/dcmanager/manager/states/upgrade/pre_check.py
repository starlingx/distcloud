#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.common.exceptions import ManualRecoveryRequiredException
from dcmanager.db import api as db_api
from dcmanager.manager.states.base import BaseState

# These deploy states should transition to the 'upgrading' state
VALID_UPGRADE_STATES = [consts.DEPLOY_STATE_INSTALL_FAILED,
                        consts.DEPLOY_STATE_DATA_MIGRATION_FAILED, ]

# These deploy states should transition to the 'migrating_data' state
VALID_MIGRATE_DATA_STATES = [consts.DEPLOY_STATE_INSTALLED, ]


class PreCheckState(BaseState):
    """This State skips to the appropriate later state based on subcloud"""

    def __init__(self):
        super(PreCheckState, self).__init__(
            next_state=consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def perform_state_action(self, strategy_step):
        """This state will check if the subcloud is offline:

        if online, proceed to INSTALLING_LICENSE state
        if offline, check the deploy_status and transfer to the correct state.
        if an unsupported deploy_status is encountered, fail the upgrade
        """
        subcloud = db_api.subcloud_get(self.context, strategy_step.subcloud.id)
        if subcloud.availability_status == consts.AVAILABILITY_ONLINE:
            return self.next_state

        # it is offline.
        if subcloud.deploy_status in VALID_UPGRADE_STATES:
            self.override_next_state(consts.STRATEGY_STATE_UPGRADING_SIMPLEX)
            return self.next_state

        if subcloud.deploy_status in VALID_MIGRATE_DATA_STATES:
            self.override_next_state(consts.STRATEGY_STATE_MIGRATING_DATA)
            return self.next_state

        # FAIL: We are offline and encountered an un-recoverable deploy status
        self.info_log(strategy_step,
                      "Un-handled deploy_status: %s" % subcloud.deploy_status)
        raise ManualRecoveryRequiredException(
            subcloud=strategy_step.subcloud.name,
            deploy_status=subcloud.deploy_status)
