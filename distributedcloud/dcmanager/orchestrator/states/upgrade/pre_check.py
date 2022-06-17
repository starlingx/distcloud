#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import copy
import re

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sysinv_v1 import HOST_FS_NAME_SCRATCH
from dcmanager.common import consts
from dcmanager.common.exceptions import ManualRecoveryRequiredException
from dcmanager.common.exceptions import PreCheckFailedException
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_SYSTEM_INFO_CACHE_TYPE

# These deploy states should transition to the 'upgrading' state
VALID_UPGRADE_STATES = [consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                        consts.DEPLOY_STATE_INSTALL_FAILED,
                        consts.DEPLOY_STATE_DATA_MIGRATION_FAILED, ]

# These deploy states should transition to the 'migrating_data' state
VALID_MIGRATE_DATA_STATES = [consts.DEPLOY_STATE_INSTALLED, ]

# These deploy states should transition to the 'activating_upgrade' state
VALID_ACTIVATION_STATES = [consts.DEPLOY_STATE_MIGRATED, ]

MIN_SCRATCH_SIZE_REQUIRED_GB = 16

UPGRADE_IN_PROGRESS_ALARM = '900.005'
HOST_ADMINISTRATIVELY_LOCKED_ALARM = '200.001'

ALARM_IGNORE_LIST = [UPGRADE_IN_PROGRESS_ALARM, ]


class PreCheckState(BaseState):
    """This State performs entry checks and skips to the appropriate state"""

    def __init__(self, region_name):
        super(PreCheckState, self).__init__(
            next_state=consts.STRATEGY_STATE_INSTALLING_LICENSE, region_name=region_name)

    def _check_health(self, strategy_step, subcloud_sysinv_client, subcloud_fm_client,
                      host, upgrades):

        # Check system health
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

        # TODO(teewrs): Update the sysinv API to allow a list of ignored alarms
        # to be passed to the health check API. This would be much more efficient
        # than having to retrieve the alarms in a separate step.
        system_health = subcloud_sysinv_client.get_system_health()
        fails = re.findall("\[Fail\]", system_health)
        failed_alarm_check = re.findall("No alarms: \[Fail\]", system_health)
        no_mgmt_alarms = re.findall("\[0\] of which are management affecting",
                                    system_health)

        alarm_ignore_list = copy.copy(ALARM_IGNORE_LIST)
        if (host.administrative == consts.ADMIN_LOCKED and upgrades):
            alarm_ignore_list.append(HOST_ADMINISTRATIVELY_LOCKED_ALARM)

        # The health conditions acceptable for upgrade are:
        # a) subcloud is completely healthy (i.e. no failed checks)
        # b) subcloud only fails alarm check and it only has non-management
        #    affecting alarm(s)
        # c) the management alarm(s) that subcloud has once upgrade has started
        #    are upgrade alarm itself and host locked alarm
        if ((len(fails) == 0) or
                (len(fails) == 1 and failed_alarm_check and no_mgmt_alarms)):
            self.info_log(strategy_step, "Health check passed.")
            return

        if not failed_alarm_check:
            # Health check failure: no alarms involved
            #
            # These could be Kubernetes or other related failure(s) which has not been been
            # converted into an alarm condition.
            details = "System health check failed. Please run 'system health-query' " \
                      "command on the subcloud for more details."
            self.error_log(strategy_step, "\n" + system_health)
            raise PreCheckFailedException(
                subcloud=strategy_step.subcloud.name,
                details=details,
                )
        else:
            # Health check failure: one or more alarms
            if (upgrades and (len(fails) == len(alarm_ignore_list))):
                # Upgrade has started, previous try failed either before or after
                # host lock.
                return
            elif len(fails) == 1:
                # Healthy check failure: exclusively alarms related
                alarms = subcloud_fm_client.get_alarms()
                for alarm in alarms:
                    if alarm.alarm_id not in alarm_ignore_list:
                        if alarm.mgmt_affecting == "True":
                            details = "System health check failed due to alarm %s. " \
                                      "Please run 'system health-query' " \
                                      "command on the subcloud for more details." % alarm.alarm_id
                            self.error_log(strategy_step, "\n" + system_health)
                            raise PreCheckFailedException(
                                subcloud=strategy_step.subcloud.name,
                                details=details,
                                )
            else:
                # Multiple failures
                details = "System health check failed due to multiple failures. " \
                          "Please run 'system health-query' command on the " \
                          "subcloud for more details."
                self.error_log(strategy_step, "\n" + system_health)
                raise PreCheckFailedException(
                    subcloud=strategy_step.subcloud.name,
                    details=details,
                    )

    def _check_scratch(self, strategy_step, subcloud_sysinv_client, host):
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

    def _perform_subcloud_online_checks(self, strategy_step, subcloud_sysinv_client,
                                        subcloud_fm_client, host, upgrades):

        self._check_health(strategy_step, subcloud_sysinv_client, subcloud_fm_client,
                           host, upgrades)

        self._check_scratch(strategy_step, subcloud_sysinv_client, host)

    def perform_state_action(self, strategy_step):
        """This state will check if the subcloud is offline:

        Check the deploy_status and transfer to the correct state.
        if an unsupported deploy_status is encountered, fail the upgrade
        """

        subcloud = db_api.subcloud_get(self.context, strategy_step.subcloud.id)

        if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:
            subcloud_sysinv_client = None
            try:
                subcloud_sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name)
                subcloud_fm_client = self.get_fm_client(strategy_step.subcloud.name)
            except Exception:
                # if getting the token times out, the orchestrator may have
                # restarted and subcloud may be offline; so will attempt
                # to use the persisted values
                message = ("Subcloud %s failed to get subcloud client" %
                           strategy_step.subcloud.name)
                self.error_log(strategy_step, message)
                error_message = "deploy state: %s" % subcloud.deploy_status
                raise ManualRecoveryRequiredException(
                    subcloud=strategy_step.subcloud.name,
                    error_message=error_message)

            host = subcloud_sysinv_client.get_host("controller-0")
            subcloud_type = self.get_sysinv_client(
                strategy_step.subcloud.name).get_system().system_mode

            upgrades = subcloud_sysinv_client.get_upgrades()
            if subcloud_type == consts.SYSTEM_MODE_SIMPLEX:
                # Check presence of data_install values.  These are managed
                # semantically on subcloud add or update
                if not subcloud.data_install:
                    details = ("Data install values are missing and must be updated "
                               "via dcmanager subcloud update")
                    raise PreCheckFailedException(
                        subcloud=strategy_step.subcloud.name,
                        details=details)

                if (host.administrative == consts.ADMIN_LOCKED and
                        (subcloud.deploy_status == consts.DEPLOY_STATE_INSTALL_FAILED or
                         subcloud.deploy_status == consts.DEPLOY_STATE_PRE_INSTALL_FAILED)):
                    # If the subcloud is online but its deploy state is pre-install-failed
                    # or install-failed and the subcloud host is locked, the upgrading
                    # simplex step must have failed early in the previous upgrade attempt.
                    # The pre-check should transition directly to upgrading simplex step in the
                    # retry.
                    self.override_next_state(consts.STRATEGY_STATE_UPGRADING_SIMPLEX)
                    return self.next_state

                # Skip subcloud online checks if the subcloud deploy status is
                # "migrated".
                if subcloud.deploy_status == consts.DEPLOY_STATE_MIGRATED:
                    self.info_log(strategy_step, "Online subcloud checks skipped.")
                else:
                    self._perform_subcloud_online_checks(strategy_step,
                                                         subcloud_sysinv_client,
                                                         subcloud_fm_client,
                                                         host, upgrades)

                if subcloud.deploy_status == consts.DEPLOY_STATE_MIGRATED:
                    # If the subcloud has completed data migration, advance directly
                    # to activating upgrade step.
                    self.override_next_state(consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
                elif subcloud.deploy_status == consts.DEPLOY_STATE_DATA_MIGRATION_FAILED:
                    # If the subcloud deploy status is data-migration-failed but
                    # it is online and has passed subcloud online checks, it must have
                    # timed out while waiting for the subcloud to reboot previously and
                    # has succesfully been unlocked since. Update the subcloud deploy
                    # status and advance to activating upgrade step.
                    db_api.subcloud_update(
                        self.context, strategy_step.subcloud_id,
                        deploy_status=consts.DEPLOY_STATE_MIGRATED)
                    self.override_next_state(consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
            else:
                # Duplex case
                if upgrades:
                    # If upgrade has started, skip subcloud online checks
                    self.info_log(strategy_step, "Online subcloud checks skipped.")
                    upgrade_state = upgrades[0].state
                    if(upgrade_state == consts.UPGRADE_STATE_DATA_MIGRATION_FAILED or
                       upgrade_state == consts.UPGRADE_STATE_DATA_MIGRATION):
                        error_message = "upgrade state: %s" % upgrade_state
                        raise ManualRecoveryRequiredException(
                            subcloud=strategy_step.subcloud.name,
                            error_message=error_message)
                    elif(upgrade_state == consts.UPGRADE_STATE_UPGRADING_CONTROLLERS or
                         upgrade_state == consts.UPGRADE_STATE_DATA_MIGRATION_COMPLETE):
                        # At this point the subcloud is duplex, deploy state is complete
                        # and "system upgrade-show" on the subcloud indicates that the
                        # upgrade state is "upgrading-controllers".
                        # If controller-1 is locked then we unlock it,
                        # if controller-0 is active we need to swact
                        # else we can proceed to create the VIM strategy.
                        controller_1_host = subcloud_sysinv_client.get_host("controller-1")
                        if controller_1_host.administrative == consts.ADMIN_LOCKED:
                            self.override_next_state(
                                consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_1)
                        elif host.capabilities.get('Personality') == consts.PERSONALITY_CONTROLLER_ACTIVE:
                            self.override_next_state(
                                consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_1)
                        else:
                            self.override_next_state(
                                consts.STRATEGY_STATE_CREATING_VIM_UPGRADE_STRATEGY)
                    elif (upgrade_state == consts.UPGRADE_STATE_UPGRADING_HOSTS):
                        # At this point the subcloud is duplex, deploy state is complete
                        # and "system upgrade-show" on the subcloud indicates that the
                        # upgrade state is "upgrading-hosts".
                        # If both subcloud hosts are upgraded to the newer load,
                        # we resume the state machine from activate upgrade state.
                        # Otherwise, we resume from create the VIM strategy state.

                        # determine the version of the system controller in region one
                        target_version = \
                            self._read_from_cache(REGION_ONE_SYSTEM_INFO_CACHE_TYPE)\
                                .software_version

                        all_hosts_upgraded = True
                        subcloud_hosts = self.get_sysinv_client(
                            strategy_step.subcloud.name).get_hosts()
                        for subcloud_host in subcloud_hosts:
                            if(subcloud_host.software_load != target_version or
                               subcloud_host.administrative == consts.ADMIN_LOCKED or
                               subcloud_host.operational == consts.OPERATIONAL_DISABLED):
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
                    elif (upgrade_state == consts.UPGRADE_STATE_ACTIVATION_FAILED):
                        if(host.capabilities.get('Personality') == consts.PERSONALITY_CONTROLLER_ACTIVE):
                            self.override_next_state(
                                consts.STRATEGY_STATE_ACTIVATING_UPGRADE)
                        else:
                            self.override_next_state(
                                consts.STRATEGY_STATE_SWACTING_TO_CONTROLLER_0)
                    elif (upgrade_state == consts.UPGRADE_STATE_ACTIVATION_COMPLETE):
                        self.override_next_state(consts.STRATEGY_STATE_COMPLETING_UPGRADE)

                else:
                    # Perform subcloud online check for duplex and proceed to the next step
                    # (i.e. installing license)
                    self._perform_subcloud_online_checks(strategy_step,
                                                         subcloud_sysinv_client,
                                                         subcloud_fm_client,
                                                         host, upgrades)
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
        error_message = "deploy state: %s" % subcloud.deploy_status
        raise ManualRecoveryRequiredException(
            subcloud=strategy_step.subcloud.name,
            error_message=error_message)
