#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import datetime
from eventlet.green import subprocess
import os

from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.manager.states.base import BaseState

ANSIBLE_UPGRADE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/upgrade_platform.yml'


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

        self.info_log(strategy_step, "Data migration completed.")
        return True
