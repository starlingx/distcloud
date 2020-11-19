#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import re

from dccommon.drivers.openstack.sysinv_v1 import HOST_FS_NAME_SCRATCH

from dcmanager.common import consts
from dcmanager.common.exceptions import ManualRecoveryRequiredException
from dcmanager.common.exceptions import PreCheckFailedException
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState

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

    def __init__(self, region_name):
        super(PreCheckState, self).__init__(
            next_state=consts.STRATEGY_STATE_INSTALLING_LICENSE, region_name=region_name)

    def _perform_subcloud_online_checks(self, strategy_step, subcloud_sysinv_client):
        # check system health
        #
        # Sample output #1
        # ================
        #     Some non-management affecting alarms, all other checks passed
        #
        # System Health:
        # All hosts are provisioned: [OK]
        # All hosts are unlocked/enabled: [OK]
        # All hosts have current configurations: [OK]
        # All hosts are patch current: [OK]
        # Ceph Storage Healthy: [OK]
        # No alarms: [Fail]
        # [1] alarms found, [0] of which are management affecting
        # All kubernetes nodes are ready: [OK]
        # All kubernetes control plane pods are ready: [OK]
        #
        # Sample output #2
        # ================
        #     Multiple failed checks, management affecting alarms
        #
        # System Health:
        # All hosts are provisioned: [OK]
        # All hosts are unlocked/enabled: [OK]
        # All hosts have current configurations: [OK]
        # All hosts are patch current: [OK]
        # Ceph Storage Healthy: [Fail]
        # No alarms: [Fail]
        # [7] alarms found, [2] of which are management affecting
        # All kubernetes nodes are ready: [OK]
        # All kubernetes control plane pods are ready: [OK]

        system_health = subcloud_sysinv_client.get_system_health()
        fails = re.findall("\[Fail\]", system_health)
        failed_alarm_check = re.findall("No alarms: \[Fail\]", system_health)
        no_mgmt_alarms = re.findall("\[0\] of which are management affecting",
                                    system_health)

        # The only 2 health conditions acceptable for upgrade are:
        # a) subcloud is completely healthy (i.e. no failed checks)
        # b) subcloud only fails alarm check and it only has non-management
        #    affecting alarm(s)
        if ((len(fails) == 0) or
                (len(fails) == 1 and failed_alarm_check and no_mgmt_alarms)):
            self.info_log(strategy_step, "health check passed.")
        else:
            details = "System health check failed. Please run 'system health-query' " \
                      "command on the subcloud for more details."
            self.error_log(strategy_step, "\n" + system_health)
            raise PreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details,
                )

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
        # check presence of data_install values.  These are managed
        # semantically on subcloud add or update
        if not subcloud.data_install:
            details = ("Data install values are missing and must be updated "
                       "via dcmanager subcloud update")
            raise PreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details)

        if subcloud.availability_status == consts.AVAILABILITY_ONLINE:
            subcloud_sysinv_client = None
            try:
                subcloud_sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name)
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

            host = subcloud_sysinv_client.get_host("controller-0")
            if (host.administrative == consts.ADMIN_LOCKED and
                    subcloud.deploy_status == consts.DEPLOY_STATE_INSTALL_FAILED):
                # If the subcloud is online but its deploy state is install-failed
                # and the subcloud host is locked, the upgrading simplex step must
                # have failed early in the previous upgrade attempt. The pre-check
                # should transition directly to upgrading simplex step in the
                # retry.
                self.override_next_state(consts.STRATEGY_STATE_UPGRADING_SIMPLEX)
                return self.next_state

            self._perform_subcloud_online_checks(strategy_step, subcloud_sysinv_client)
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
