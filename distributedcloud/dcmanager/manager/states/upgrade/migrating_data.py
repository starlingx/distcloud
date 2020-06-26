#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import datetime
from eventlet.green import subprocess
import os
import time

from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyStoppedException
from dcmanager.db import api as db_api
from dcmanager.manager.states.base import BaseState

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


# TODO(tngo): Create a utility function that invokes ansible playbook for various
# dcmanager use cases (subcloud add, remote install and platform upgrade).
def migrate_subcloud_data(subcloud_name, migrate_command):
    log_file = (consts.DC_LOG_DIR + subcloud_name + '_migrate_' +
                str(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
                + '.log')
    with open(log_file, "w") as f_out_log:
        try:
            subprocess.check_call(migrate_command,
                                  stdout=f_out_log,
                                  stderr=f_out_log)
        except subprocess.CalledProcessError:
            msg = ("Failed to migrate data for subcloud %s, check individual "
                   "log at %s for detailed output."
                   % (subcloud_name, log_file))
            raise Exception(msg)


class MigratingDataState(BaseState):
    """Upgrade step for migrating data"""

    def __init__(self):
        super(MigratingDataState, self).__init__()

        self.ansible_sleep = DEFAULT_ANSIBLE_SLEEP
        self.max_api_queries = DEFAULT_MAX_API_QUERIES
        self.api_sleep_duration = DEFAULT_API_SLEEP
        self.max_failed_queries = DEFAULT_MAX_FAILED_QUERIES
        self.failed_sleep_duration = DEFAULT_FAILED_SLEEP

    def is_subcloud_data_migration_required(self, strategy_step):
        local_ks_client = self.get_keystone_client()
        local_sysinv_client = \
            self.get_sysinv_client(consts.DEFAULT_REGION_NAME,
                                   local_ks_client.session)
        sc_version = local_sysinv_client.get_system().software_version

        try:
            ks_client = self.get_keystone_client(strategy_step.subcloud.name)
            sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                                   ks_client.session)
            subcloud_version = sysinv_client.get_system().software_version
            if subcloud_version == sc_version:
                self.debug_log(strategy_step, "Subcloud upgrade is already done.")
            else:
                # Subcloud data migration is complete but not yet activated
                self.info_log(strategy_step, "Data migration is already done.")

            return False
        except Exception as e:
            # After a fresh install, subcloud keystone is not yet accessible
            self.info_log(strategy_step, str(e))
            return True

    def wait_for_unlock(self, strategy_step):
        """This method returns successfully when the unlock completes.

        An exception is raised if it does not recover on time.
        """

        # This code is 'borrowed' from the unlock_host state
        # Allow separate durations for failures (ie: reboot) and api retries
        api_counter = 0
        fail_counter = 0
        # Allow just one failed auth (token expired)
        auth_failure = False
        # todo(abailey): only supports AIO-SX here
        target_hostname = 'controller-0'
        ks_client = None
        sysinv_client = None
        while True:
            # If event handler stop has been triggered, fail the state
            if self.stopped():
                raise StrategyStoppedException()
            try:
                # Create a sysinv client on the subcloud
                if ks_client is None:
                    ks_client = \
                        self.get_keystone_client(strategy_step.subcloud.name)
                if sysinv_client is None:
                    sysinv_client = \
                        self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)
                # query the administrative state to see if it is the new state.
                host = sysinv_client.get_host(target_hostname)
                if (host.administrative == consts.ADMIN_UNLOCKED and
                        host.operational == consts.OPERATIONAL_ENABLED):
                    # Success. Break out of the loop.
                    msg = "Host: %s is now: %s %s" % (target_hostname,
                                                      host.administrative,
                                                      host.operational)
                    self.info_log(strategy_step, msg)
                    break
                # no exception was raised so reset fail and auth checks
                auth_failure = False
                fail_counter = 0
            except Exception as e:
                if str(e) == "Authorization failed":
                    # Since a token could expire while waiting, generate
                    # a new token (by re-creating the client) and re-try the
                    # request, but only once.
                    if not auth_failure:
                        auth_failure = True
                        self.info_log(strategy_step,
                                      "Authorization failure. Retrying...")
                        ks_client = self.get_keystone_client(
                            strategy_step.subcloud.name)
                        sysinv_client = self.get_sysinv_client(
                            strategy_step.subcloud.name,
                            ks_client.session)
                        continue
                    else:
                        raise Exception("Repeated authorization failures.")
                else:
                    # Handle other exceptions due to being unreachable
                    # for a significant period of time when there is a
                    # controller swact, or in the case of AIO-SX,
                    # when the controller reboots.
                    fail_counter += 1
                    if fail_counter >= self.max_failed_queries:
                        raise Exception("Timeout waiting on reboot to complete")
                    time.sleep(self.failed_sleep_duration)
                    # skip the api_counter
                    continue
            # If the max counter is exceeeded, raise a timeout exception
            api_counter += 1
            if api_counter >= self.max_api_queries:
                raise Exception("Timeout waiting for unlock to complete")
            time.sleep(self.api_sleep_duration)

    def perform_state_action(self, strategy_step):
        """Migrate data for an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """

        if not self.is_subcloud_data_migration_required(strategy_step):
            self.info_log(strategy_step, "Data migration is already done.")
            return True

        self.info_log(strategy_step, "Start migrating data...")
        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_MIGRATING_DATA)

        ansible_subcloud_inventory_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH,
            strategy_step.subcloud.name + consts.INVENTORY_FILE_POSTFIX)

        data_migrating_cmd = [
            "ansible-playbook", ANSIBLE_UPGRADE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file, "-e",
            "ansible_ssh_pass=%s ansible_become_pass=%s"
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

        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_DONE)

        # Ansible invokes an unlock. Need to wait for the unlock to complete.
        # Wait for 3 minutes for mtc/scripts to shut down services
        # todo(abailey): split this into smaller sleeps to allow stopping early
        time.sleep(self.ansible_sleep)
        # wait up to 60 minutes for reboot to complete
        self.wait_for_unlock(strategy_step)

        self.info_log(strategy_step, "Data migration completed.")
        return True
