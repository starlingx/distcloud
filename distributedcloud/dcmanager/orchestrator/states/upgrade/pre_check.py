#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
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
        subcloud_type = self.get_sysinv_client(
            strategy_step.subcloud.name).get_system().system_mode
        upgrades = self.get_sysinv_client(strategy_step.subcloud.name).get_upgrades()

        # For duplex upgrade, we skip health checks if an upgrade is in progress.

        if (len(upgrades) != 0 and subcloud_type == consts.SYSTEM_MODE_DUPLEX):
            self.info_log(strategy_step, "Health check skipped for non-simplex subclouds.")
        else:
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
            # The only 2 health conditions acceptable for simplex upgrade are:
            # a) subcloud is completely healthy (i.e. no failed checks)
            # b) subcloud only fails alarm check and it only has non-management
            #    affecting alarm(s)

            if ((len(fails) == 0) or
                    (len(fails) == 1 and failed_alarm_check and no_mgmt_alarms)):
                self.info_log(strategy_step, "Health check passed.")
            else:
                details = "System health check failed. " \
                          "Please run 'system health-query' " \
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
            subcloud_type = self.get_sysinv_client(
                strategy_step.subcloud.name).get_system().system_mode

            # Check presence of data_install values.  These are managed
            # semantically on subcloud add or update
            if subcloud_type == consts.SYSTEM_MODE_SIMPLEX and not subcloud.data_install:
                details = ("Data install values are missing and must be updated "
                           "via dcmanager subcloud update")
                raise PreCheckFailedException(
                    subcloud=strategy_step.subcloud.name,
                    details=details)

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

            if (subcloud_type == consts.SYSTEM_MODE_DUPLEX and
                    subcloud.deploy_status == consts.DEPLOY_STATE_DONE):
                upgrades = self.get_sysinv_client(strategy_step.subcloud.name).get_upgrades()

                if len(upgrades) != 0:
                    upgrade_state = upgrades[0].state
                    if(upgrade_state == consts.UPGRADE_STATE_UPGRADING_CONTROLLERS):
                        # At this point the subcloud is duplex, deploy state is complete
                        # and "system upgrade-show" on the subcloud indicates that the
                        # upgrade state is "upgrading-controllers".
                        # If controller-0 is the active controller, we need to swact
                        # else we can proceed to create the VIM strategy.
                        if host.capabilities.get('Personality') == consts.PERSONALITY_CONTROLLER_ACTIVE:
                            self.override_next_state(
                                consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1)
                        else:
                            self.override_next_state(
                                consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY)
                    elif(upgrade_state == consts.UPGRADE_STATE_UPGRADING_HOSTS):
                        # At this point the subcloud is duplex, deploy state is complete
                        # and "system upgrade-show" on the subcloud indicates that the
                        # upgrade state is "upgrading-hosts".
                        # If both subcloud hosts are upgraded to the newer load,
                        # we resume the state machine from activate upgrade state.
                        # Otherwise, we resume from create the VIM strategy state.

                        # determine the version of the system controller in region one
                        target_version = self.get_sysinv_client(consts.DEFAULT_REGION_NAME).\
                            get_system().software_version

                        all_hosts_upgraded = True
                        subcloud_hosts = self.get_sysinv_client(
                            strategy_step.subcloud.name).get_hosts()
                        for subcloud_host in subcloud_hosts:
                            if(subcloud_host.software_load != target_version):
                                all_hosts_upgraded = False
                                self.override_next_state(
                                    consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY)

                        if all_hosts_upgraded:
                            if host.capabilities.get('Personality') == consts.PERSONALITY_CONTROLLER_ACTIVE:
                                self.override_next_state(
                                    consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
                            else:
                                self.override_next_state(
                                    consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0)
                    elif(upgrade_state == consts.UPGRADE_STATE_ACTIVATION_FAILED):
                        if(host.capabilities.get('Personality') == consts.PERSONALITY_CONTROLLER_ACTIVE):
                            self.override_next_state(
                                consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
                        else:
                            self.override_next_state(
                                consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0)
                    elif(upgrade_state == consts.UPGRADE_STATE_ACTIVATION_COMPLETE):
                        self.override_next_state(consts.STRATEGY_STATE_COMPLETING_UPGRADE)
            return self.next_state

        # If it gets here, the subcloud must be offline and is a simplex
        if subcloud.deploy_status in VALID_UPGRADE_STATES:
            if not subcloud.data_install:
                details = ("Data install values are missing and must be updated "
                           "via dcmanager subcloud update")
                raise PreCheckFailedException(
                    subcloud=strategy_step.subcloud.name,
                    details=details)

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
