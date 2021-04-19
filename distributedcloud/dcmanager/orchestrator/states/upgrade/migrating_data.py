#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import time

from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.utils import run_playbook
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState


ANSIBLE_UPGRADE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/upgrade_platform.yml'

# When an unlock occurs, a reboot is triggered. During reboot, API calls fail.
# The max time allowed here is 30 minutes (ie: 30 queries with 1 minute sleep)
DEFAULT_MAX_FAILED_QUERIES = 30
DEFAULT_FAILED_SLEEP = 60

# after reboot, the unlock needs to do post-reboot activities during which
# time the API will succeed, but the expected states will not yet be set.
# The max time allowed here is 30 minutes (ie: 30 queries with 1 minute sleep)
DEFAULT_MAX_API_QUERIES = 30
DEFAULT_API_SLEEP = 60

# sleep for 3 minutes after ansible completes
DEFAULT_ANSIBLE_SLEEP = 180


def migrate_subcloud_data(subcloud_name, migrate_command):
    log_file = os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud_name) + \
        '_playbook_output.log'
    try:
        run_playbook(log_file, migrate_command)
    except PlaybookExecutionFailed:
        msg = ("Failed to migrate data for subcloud %s, check individual "
               "log at %s for detailed output."
               % (subcloud_name, log_file))
        raise Exception(msg)


class MigratingDataState(BaseState):
    """Upgrade step for migrating data"""

    def __init__(self, region_name):
        super(MigratingDataState, self).__init__(
            next_state=consts.STRATEGY_STATE_UNLOCKING_CONTROLLER_0, region_name=region_name)

        self.ansible_sleep = DEFAULT_ANSIBLE_SLEEP
        self.max_api_queries = DEFAULT_MAX_API_QUERIES
        self.api_sleep_duration = DEFAULT_API_SLEEP
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def wait_for_unlock(self, strategy_step):
        """This method returns successfully when the unlock completes.

        An exception is raised if it does not recover on time.
        """

        # This code is 'borrowed' from the unlock_host state
        # Allow separate durations for failures (ie: reboot) and api retries
        api_counter = 0
        fail_counter = 0
        # todo(abailey): only supports AIO-SX here
        target_hostname = 'controller-0'
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                # query the administrative state to see if it is the new state.
                host = self.get_sysinv_client(
                    strategy_step.subcloud.name).get_host(target_hostname)
                if (host.administrative == consts.ADMIN_UNLOCKED and
                        host.operational == consts.OPERATIONAL_ENABLED):
                    # Success. Break out of the loop.
                    msg = "Host: %s is now: %s %s" % (target_hostname,
                                                      host.administrative,
                                                      host.operational)
                    self.info_log(strategy_step, msg)
                    break
                # no exception was raised so reset fail and auth checks
                fail_counter = 0
            except Exception:
                # Handle other exceptions due to being unreachable
                # for a significant period of time when there is a
                # controller swact, or in the case of AIO-SX,
                # when the controller reboots.
                fail_counter += 1
                if fail_counter >= self.max_failed_queries:
                    db_api.subcloud_update(
                        self.context, strategy_step.subcloud_id,
                        deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)
                    raise Exception("Timeout waiting on reboot to complete")
                time.sleep(self.failed_sleep_duration)
                # skip the api_counter
                continue
            # If the max counter is exceeeded, raise a timeout exception
            api_counter += 1
            if api_counter >= self.max_api_queries:
                db_api.subcloud_update(
                    self.context, strategy_step.subcloud_id,
                    deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)
                raise Exception("Timeout waiting for unlock to complete")
            time.sleep(self.api_sleep_duration)

    def perform_state_action(self, strategy_step):
        """Migrate data for an upgrade on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        # To account for abrupt termination of dcmanager, check the last known
        # subcloud deploy status. If it is migrated/complete, advance to the next
        # stage. If it is 'migrating', fail the strategy. The user will need to
        # delete the existing strategy, create a new one and apply. Pre-check will
        # set the appropriate next step for this subcloud.
        subcloud = db_api.subcloud_get(self.context, strategy_step.subcloud.id)
        if (subcloud.deploy_status == consts.DEPLOY_STATE_MIGRATED or
                subcloud.deploy_status == consts.DEPLOY_STATE_DONE):
            return self.next_state
        elif subcloud.deploy_status == consts.DEPLOY_STATE_MIGRATING_DATA:
            db_api.subcloud_update(
                self.context, strategy_step.subcloud_id,
                deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)
            raise Exception("Previous data migration was abruptly terminated. "
                            "Please try again with a new upgrade strategy.")

        # If it gets here, the subcloud deploy status must be 'installed'.
        self.info_log(strategy_step, "Start migrating data...")
        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_MIGRATING_DATA)

        ansible_subcloud_inventory_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH,
            strategy_step.subcloud.name + consts.INVENTORY_FILE_POSTFIX)

        # Send skip_patching=true to prevent the playbook from applying any patches present in the
        # upgrade_data. All the required patches will be included in the generated install iso.
        data_migrating_cmd = [
            "ansible-playbook", ANSIBLE_UPGRADE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file, "-e",
            "ansible_ssh_pass=%s ansible_become_pass=%s skip_patching=true"
            % (consts.TEMP_SYSADMIN_PASSWORD, consts.TEMP_SYSADMIN_PASSWORD)]

        try:
            migrate_subcloud_data(strategy_step.subcloud.name,
                                  data_migrating_cmd)
        except Exception as e:
            db_api.subcloud_update(
                self.context, strategy_step.subcloud_id,
                deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)
            self.error_log(strategy_step, str(e))
            raise

        # Ansible invokes an unlock. Need to wait for the unlock to complete.
        # Wait for 3 minutes for mtc/scripts to shut down services
        # todo(abailey): split this into smaller sleeps to allow stopping early
        time.sleep(self.ansible_sleep)
        # wait up to 60 minutes for reboot to complete
        self.wait_for_unlock(strategy_step)

        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_MIGRATED)

        self.info_log(strategy_step, "Data migration completed.")
        return self.next_state
