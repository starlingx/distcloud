#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import keyring
import os

from base64 import b64encode
from dccommon.install_consts import ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK
from dccommon.subcloud_install import SubcloudInstall

from dcmanager.common import consts
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator.states.base import BaseState

from tsconfig.tsconfig import SW_VERSION


class UpgradingSimplexState(BaseState):
    """Upgrade state for upgrading a simplex subcloud host"""

    def __init__(self, region_name):
        super(UpgradingSimplexState, self).__init__(
            next_state=consts.STRATEGY_STATE_MIGRATING_DATA, region_name=region_name)

    def perform_state_action(self, strategy_step):
        """Upgrade a simplex host on a subcloud

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        self.info_log(strategy_step, "Performing simplex upgrade for subcloud")

        subcloud_sysinv_client = None
        subcloud_barbican_client = None
        try:
            subcloud_sysinv_client = self.get_sysinv_client(
                strategy_step.subcloud.name)
            subcloud_barbican_client = self.get_barbican_client(
                strategy_step.subcloud.name)
        except Exception:
            # if getting the token times out, the orchestrator may have
            # restarted and subcloud may be offline; so will attempt
            # to use the persisted values
            message = ("Simplex upgrade perform_subcloud_install "
                       "subcloud %s failed to get subcloud client" %
                       strategy_step.subcloud.name)
            self.error_log(strategy_step, message)
            pass

        # Check whether subcloud is already re-installed with N+1 load
        target_version = SW_VERSION
        if self._check_load_already_active(
                target_version, subcloud_sysinv_client):
            self.info_log(strategy_step,
                          "Load:%s already active" % target_version)
            return self.next_state

        # Check whether subcloud supports redfish, and if not, fail.
        # This needs to be inferred from absence of install_values as
        # there is currrently no external api to query.
        install_values = self.get_subcloud_upgrade_install_values(
            strategy_step, subcloud_sysinv_client, subcloud_barbican_client)

        local_ks_client = self.get_keystone_client()

        # Upgrade the subcloud to the install_values image
        self.perform_subcloud_install(
            strategy_step, local_ks_client.session, install_values)
        return self.next_state

    def _check_load_already_active(self, target_version, subcloud_sysinv_client):
        """Check if the target_version is already active in subcloud"""

        if subcloud_sysinv_client:
            current_loads = subcloud_sysinv_client.get_loads()
            for load in current_loads:
                if (load.software_version == target_version and
                        load.state == 'active'):
                    return True
        return False

    def get_subcloud_upgrade_install_values(
            self, strategy_step,
            subcloud_sysinv_client, subcloud_barbican_client):
        """Get the data required for the remote subcloud install.

        subcloud data_install are obtained from:

        dcmanager database:
            subcloud.subcloud_install_initial::for values which are persisted at subcloud_add time

            INSTALL: (needed for upgrade install)
                bootstrap_interface
                bootstrap_vlan
                bootstrap_address
                bootstrap_address_prefix
                install_type  # could also be from host-show

                # This option can be set to extend the installing stage timeout value
                # wait_for_timeout: 3600

                # Set this options for https with self-signed certificate
                # no_check_certificate

                # Override default filesystem device: also from host-show, but is static.
                # rootfs_device: "/dev/disk/by-path/pci-0000:00:1f.2-ata-1.0"
                # boot_device: "/dev/disk/by-path/pci-0000:00:1f.2-ata-1.0"

                # Set rd.net.timeout.ipv6dad to increase timeout on IPv6 NIC up
                # rd.net.timeout.ipv6dad: 300

            BOOTSTRAP: (also needed for bootstrap)
                # If the subcloud's bootstrap IP interface and the system controller are not on the
                # same network then the customer must configure a default route or static route
                # so that the Central Cloud can login bootstrap the newly installed subcloud.
                # If nexthop_gateway is specified and the network_address is not specified then a
                # default route will be configured. Otherwise, if a network_address is specified
                then
                # a static route will be configured.
                nexthop_gateway: default_route_address
                network_address: static_route_address
                network_mask: static_route_mask

            subcloud.data_upgrade - persist for upgrade duration
                for values from subcloud online sysinv host-show (persist since upgrade-start)
                    bmc_address  # sysinv_v1 host-show
                    bmc_username # sysinv_v1 host-show
                for values from barbican_client (as barbican user), or from upgrade-start:
                    bmc_password --- obtain from barbican_client as barbican user
        """

        install_values = {'name': strategy_step.subcloud.name}

        install_values.update(
            self._get_subcloud_upgrade_load_info(strategy_step))

        upgrade_data_install_values = self._get_subcloud_upgrade_data_install(
            strategy_step)
        install_values.update(upgrade_data_install_values)

        install_values.update(
            self._get_subcloud_upgrade_data(
                strategy_step, subcloud_sysinv_client, subcloud_barbican_client))

        # Check bmc values
        if not self._bmc_data_available(install_values):
            if self._bmc_data_available(upgrade_data_install_values):
                # It is possible the bmc data is only latched on install if it
                # was not part of the deployment configuration
                install_values.update({
                    'bmc_address':
                        upgrade_data_install_values.get('bmc_address'),
                    'bmc_username':
                        upgrade_data_install_values.get('bmc_username'),
                    'bmc_password':
                        upgrade_data_install_values.get('bmc_password'),
                })
            else:
                message = ("Failed to get bmc credentials for subcloud %s" %
                           strategy_step.subcloud.name)
                raise Exception(message)

        self.info_log(strategy_step,
                      "get_subcloud_upgrade_data_install %s" % install_values)
        return install_values

    @staticmethod
    def _bmc_data_available(bmc_values):
        if (not bmc_values.get('bmc_username') or
                not bmc_values.get('bmc_address') or
                not bmc_values.get('bmc_password')):
            return False
        return True

    def _get_subcloud_upgrade_load_info(self, strategy_step):
        """Get the subcloud upgrade load information"""

        # The 'software_version' is the active running load on SystemController
        matching_iso, _ = utils.get_vault_load_files(SW_VERSION)
        if not matching_iso:
            message = ("Failed to get upgrade load info for subcloud %s" %
                       strategy_step.subcloud.name)
            raise Exception(message)

        load_info = {'software_version': SW_VERSION,
                     'image': matching_iso}

        return load_info

    def _get_subcloud_upgrade_data_install(self, strategy_step):
        """Get subcloud upgrade data_install from persisted values"""

        upgrade_data_install = {}

        subcloud = db_api.subcloud_get(self.context, strategy_step.subcloud_id)
        if not subcloud.data_install:
            # Set the deploy status to pre-install-failed so it can be
            # handled accordingly in pre check step.
            db_api.subcloud_update(
                self.context, strategy_step.subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)

            message = ("Failed to get upgrade data from install")
            self.warn_log(strategy_step, message)
            raise Exception(message)

        data_install = json.loads(subcloud.data_install)

        # base64 encoded sysadmin_password is default
        upgrade_data_install.update({
            'ansible_become_pass': consts.TEMP_SYSADMIN_PASSWORD,
            'ansible_ssh_pass': consts.TEMP_SYSADMIN_PASSWORD,
        })
        # Get mandatory bootstrap info from data_install
        # bootstrap_address is referenced in SubcloudInstall
        # bootstrap-address is referenced in create_subcloud_inventory and
        # subcloud manager.
        # todo(jkung): refactor to just use one bootstrap address index
        upgrade_data_install.update({
            'bootstrap_interface': data_install.get('bootstrap_interface'),
            'bootstrap-address': data_install.get('bootstrap_address'),
            'bootstrap_address': data_install.get('bootstrap_address'),
            'bootstrap_address_prefix': data_install.get('bootstrap_address_prefix'),
            'bmc_username': data_install.get('bmc_username'),
            'bmc_address': data_install.get('bmc_address'),
            'bmc_password': data_install.get('bmc_password'),
        })

        # optional bootstrap parameters
        optional_bootstrap_parameters = [
            'nexthop_gateway',  # default route address
            'network_address',  # static route address
            'network_mask',  # static route mask
            'bootstrap_vlan',
            'wait_for_timeout',
            'no_check_certificate',
            'rd.net.timeout.ipv6dad',
        ]

        for p in optional_bootstrap_parameters:
            if p in data_install:
                upgrade_data_install.update({p: data_install.get(p)})

        return upgrade_data_install

    def _get_subcloud_upgrade_data(
        self, strategy_step, subcloud_sysinv_client, subcloud_barbican_client):
        """Get the subcloud data required for upgrades.

           In case the subcloud is no longer reachable, get upgrade_data from
           persisted database values.  For example, this may be required in
           the scenario where the subcloud experiences an unexpected error
           (e.g. loss of power) and this step needs to be rerun.
        """

        volatile_data_install = {}

        if subcloud_sysinv_client is None:
            # subcloud is not reachable, use previously saved values
            subcloud = db_api.subcloud_get(
                self.context, strategy_step.subcloud_id)
            if subcloud.data_upgrade:
                return json.loads(subcloud.data_upgrade)
            else:
                message = ('Cannot retrieve upgrade data install '
                           'for subcloud: %s' %
                           strategy_step.subcloud.name)
                raise Exception(message)

        subcloud_system = subcloud_sysinv_client.get_system()

        if subcloud_system.system_type != 'All-in-one':
            message = ('subcloud %s install unsupported for system type: %s' %
                       (strategy_step.subcloud.name,
                        subcloud_system.system_type))
            raise Exception(message)

        host = subcloud_sysinv_client.get_host('controller-0')

        install_type = self._get_install_type(host)

        bmc_password = None
        if subcloud_barbican_client:
            bmc_password = subcloud_barbican_client.get_host_bmc_password(host.uuid)
            if bmc_password:
                # If the host is configured to store bmc in its barbican database,
                # encode the password. Otherwise leave it as None and it will be
                # replaced with the value retrieved from the dcmanager database.
                bmc_password = b64encode(bmc_password)

        volatile_data_install.update({
            'bmc_address': host.bm_ip,
            'bmc_username': host.bm_username,
            'bmc_password': bmc_password,
            'install_type': install_type,
            'boot_device': host.boot_device,
            'rootfs_device': host.rootfs_device,
        })

        # Persist the volatile data
        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            data_upgrade=json.dumps(volatile_data_install))

        admin_password = str(keyring.get_password('CGCS', 'admin'))
        volatile_data_install.update({'admin_password': admin_password})

        return volatile_data_install

    @staticmethod
    def _get_install_type(host):
        if 'lowlatency' in host.subfunctions.split(','):
            lowlatency = True
        else:
            lowlatency = False

        if 'graphical' in host.console.split(','):  # graphical console
            if lowlatency:
                install_type = 5
            else:
                install_type = 3
        else:  # serial console
            if lowlatency:
                install_type = 4
            else:
                install_type = 2
        return install_type

    def perform_subcloud_install(self, strategy_step, session, install_values):

        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)
        self.context.auth_token = session.get_token()
        self.context.project = session.get_project_id()
        try:
            install = SubcloudInstall(
                self.context, strategy_step.subcloud.name)
            install.prep(consts.ANSIBLE_OVERRIDES_PATH,
                         install_values)
        except Exception as e:
            db_api.subcloud_update(
                self.context, strategy_step.subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)
            self.error_log(strategy_step, str(e))
            # TODO(jkung): cleanup to be implemented within SubcloudInstall
            install.cleanup()
            raise

        ansible_subcloud_inventory_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH,
            strategy_step.subcloud.name + consts.INVENTORY_FILE_POSTFIX)

        # Create the ansible inventory for the upgrade subcloud
        utils.create_subcloud_inventory(install_values,
                                        ansible_subcloud_inventory_file)

        # SubcloudInstall.prep creates data_install.yml (install overrides)
        install_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
                  strategy_step.subcloud.name + '/' + "install_values.yml"
        ]

        # Run the remote install playbook
        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_INSTALLING)
        try:
            install.install(consts.DC_ANSIBLE_LOG_DIR, install_command)
        except Exception as e:
            db_api.subcloud_update(
                self.context, strategy_step.subcloud_id,
                deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)
            self.error_log(strategy_step, str(e))
            install.cleanup()
            raise

        db_api.subcloud_update(
            self.context, strategy_step.subcloud_id,
            deploy_status=consts.DEPLOY_STATE_INSTALLED)
        install.cleanup()
        self.info_log(strategy_step, "Successfully installed subcloud")
