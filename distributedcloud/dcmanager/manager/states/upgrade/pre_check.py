#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dccommon.drivers.openstack.sysinv_v1 import HOST_FS_NAME_SCRATCH

from dcmanager.common import consts
from dcmanager.common.exceptions import ManualRecoveryRequiredException
from dcmanager.common.exceptions import PreCheckFailedException
from dcmanager.db import api as db_api
from dcmanager.manager.states.base import BaseState

# These deploy states should transition to the 'upgrading' state
VALID_UPGRADE_STATES = [consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                        consts.DEPLOY_STATE_INSTALL_FAILED,
                        consts.DEPLOY_STATE_DATA_MIGRATION_FAILED, ]

# These deploy states should transition to the 'migrating_data' state
VALID_MIGRATE_DATA_STATES = [consts.DEPLOY_STATE_INSTALLED, ]

# These deploy states should transition to the 'activating_upgrade' state
VALID_ACTIVATION_STATES = [consts.DEPLOY_STATE_MIGRATED, ]

MIN_SCRATCH_SIZE_REQUIRED_GB = 16


class PreCheckState(BaseState):
    """This State performs entry checks and skips to the appropriate state"""

    def __init__(self):
        super(PreCheckState, self).__init__(
            next_state=consts.STRATEGY_STATE_INSTALLING_LICENSE)

    def _perform_subcloud_online_checks(self, strategy_step, subcloud):

        # check presence of data_install values.  These are managed
        # semantically on subcloud add or update
        if not subcloud.data_install:
            details = ("Data install values are missing and must be updated "
                       "via dcmanager subcloud update")
            raise PreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details)

        # obtain necessary clients
        subcloud_sysinv_client = None
        try:
            subcloud_ks_client = \
                self.get_keystone_client(strategy_step.subcloud.name)
            subcloud_sysinv_client = self.get_sysinv_client(
                strategy_step.subcloud.name,
                subcloud_ks_client.session)
        except Exception:
            # if getting the token times out, the orchestrator may have
            # restarted and subcloud may be offline; so will attempt
            # to use the persisted values
            message = ("_perform_subcloud_online_checks subcloud %s "
                       "failed to get subcloud client" %
                       strategy_step.subcloud.name)
            self.error_log(strategy_step, message)
            raise ManualRecoveryRequiredException(
                subcloud=strategy_step.subcloud.name,
                deploy_status=subcloud.deploy_status)

        # check scratch
        host = subcloud_sysinv_client.get_host("controller-0")
        scratch_fs = subcloud_sysinv_client.get_host_filesystem(
            host.uuid, HOST_FS_NAME_SCRATCH)
        if scratch_fs.size < MIN_SCRATCH_SIZE_REQUIRED_GB:
            details = ("Scratch filesystem size of %s does not meet "
                       "minimum required %s" %
                       (scratch_fs.size, MIN_SCRATCH_SIZE_REQUIRED_GB))
            raise PreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details,
                )

    def perform_state_action(self, strategy_step):
        """This state will check if the subcloud is offline:

        Check the deploy_status and transfer to the correct state.
        if an unsupported deploy_status is encountered, fail the upgrade
        """
        subcloud = db_api.subcloud_get(self.context, strategy_step.subcloud.id)
        if subcloud.availability_status == consts.AVAILABILITY_ONLINE:
            self._perform_subcloud_online_checks(strategy_step, subcloud)
            # If the subcloud has completed data migration and is online,
            # advance directly to activating upgrade step. Otherwise, start
            # from installing license step.
            if subcloud.deploy_status == consts.DEPLOY_STATE_MIGRATED:
                self.override_next_state(consts.STRATEGY_STATE_ACTIVATING_UPGRADE)

            return self.next_state

        # it is offline.
        if subcloud.deploy_status in VALID_UPGRADE_STATES:
            self.override_next_state(consts.STRATEGY_STATE_UPGRADING_SIMPLEX)
            return self.next_state

        elif subcloud.deploy_status in VALID_MIGRATE_DATA_STATES:
            self.override_next_state(consts.STRATEGY_STATE_MIGRATING_DATA)
            return self.next_state

        elif subcloud.deploy_status in VALID_ACTIVATION_STATES:
            self.override_next_state(consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
            return self.next_state

        # FAIL: We are offline and encountered an un-recoverable deploy status
        self.info_log(strategy_step,
                      "Un-handled deploy_status: %s" % subcloud.deploy_status)
        raise ManualRecoveryRequiredException(
            subcloud=strategy_step.subcloud.name,
            deploy_status=subcloud.deploy_status)
