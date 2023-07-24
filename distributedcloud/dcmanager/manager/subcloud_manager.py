# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import division

import collections
import datetime
import filecmp
import functools
import json
import os
import shutil
import threading
import time

from cgtsclient.exc import HTTPConflict
from eventlet import greenpool
from fm_api import constants as fm_const
from fm_api import fm_api
import keyring
import netaddr
from oslo_log import log as logging
from oslo_messaging import RemoteError
from tsconfig.tsconfig import CONFIG_PATH
from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon import kubeoperator
from dccommon.subcloud_install import SubcloudInstall
from dccommon.subcloud_install import SubcloudShutdown
from dccommon.utils import run_playbook
from dccommon.utils import RunAnsible
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common.consts import INVENTORY_FILE_POSTFIX
from dcmanager.common import context as dcmanager_context
from dcmanager.common import exceptions
from dcmanager.common.exceptions import DCManagerException
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy.models import Subcloud
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.rpc import client as dcorch_rpc_client


LOG = logging.getLogger(__name__)

# Name of our distributed cloud addn_hosts file for dnsmasq
# to read.  This file is referenced in dnsmasq.conf
ADDN_HOSTS_DC = 'dnsmasq.addn_hosts_dc'

# Subcloud configuration paths
ANSIBLE_SUBCLOUD_BACKUP_CREATE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/create_subcloud_backup.yml'
ANSIBLE_SUBCLOUD_BACKUP_DELETE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/delete_subcloud_backup.yml'
ANSIBLE_SUBCLOUD_BACKUP_RESTORE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/restore_subcloud_backup.yml'
ANSIBLE_SUBCLOUD_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/bootstrap.yml'
ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/rehome_subcloud.yml'
ANSIBLE_SUBCLOUD_UPDATE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/update_subcloud.yml'

USERS_TO_REPLICATE = [
    'sysinv',
    'patching',
    'vim',
    'mtce',
    'fm',
    'barbican',
    'dcmanager'
]

# The timeout of the rehome playbook is set to 180 seconds as it takes a
# long time for privilege escalation before resetting the host route and
# LDAP server address in a subcloud.
REHOME_PLAYBOOK_TIMEOUT = "180"  # 180 seconds
UPDATE_PLAYBOOK_TIMEOUT = "180"
SC_INTERMEDIATE_CERT_DURATION = "8760h"  # 1 year = 24 hours x 365
SC_INTERMEDIATE_CERT_RENEW_BEFORE = "720h"  # 30 days
CERT_NAMESPACE = "dc-cert"

TRANSITORY_STATES = {
    consts.DEPLOY_STATE_NONE: consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
    consts.DEPLOY_STATE_PRE_DEPLOY: consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
    consts.DEPLOY_STATE_CREATING: consts.DEPLOY_STATE_CREATE_FAILED,
    consts.DEPLOY_STATE_PRE_INSTALL: consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALLING: consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_PRE_BOOTSTRAP: consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_BOOTSTRAPPING: consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_PRE_CONFIG: consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    consts.DEPLOY_STATE_CONFIGURING: consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_DEPLOYING: consts.DEPLOY_STATE_DEPLOY_FAILED,
    consts.DEPLOY_STATE_ABORTING_INSTALL: consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_ABORTING_BOOTSTRAP: consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_ABORTING_CONFIG: consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_MIGRATING_DATA: consts.DEPLOY_STATE_DATA_MIGRATION_FAILED,
    consts.DEPLOY_STATE_PRE_RESTORE: consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
    consts.DEPLOY_STATE_RESTORING: consts.DEPLOY_STATE_RESTORE_FAILED,
    consts.PRESTAGE_STATE_PACKAGES: consts.PRESTAGE_STATE_FAILED,
    consts.PRESTAGE_STATE_IMAGES: consts.PRESTAGE_STATE_FAILED,
}


TRANSITORY_BACKUP_STATES = {
    consts.BACKUP_STATE_VALIDATING: consts.BACKUP_STATE_VALIDATE_FAILED,
    consts.BACKUP_STATE_PRE_BACKUP: consts.BACKUP_STATE_PREP_FAILED,
    consts.BACKUP_STATE_IN_PROGRESS: consts.BACKUP_STATE_FAILED
}

MAX_PARALLEL_SUBCLOUD_BACKUP_CREATE = 250
MAX_PARALLEL_SUBCLOUD_BACKUP_DELETE = 250
MAX_PARALLEL_SUBCLOUD_BACKUP_RESTORE = 100
CENTRAL_BACKUP_DIR = '/opt/dc-vault/backups'

ENDPOINT_URLS = {
    dccommon_consts.ENDPOINT_TYPE_PLATFORM: "https://{}:6386/v1",
    dccommon_consts.ENDPOINT_TYPE_IDENTITY: "https://{}:5001/v3",
    dccommon_consts.ENDPOINT_TYPE_PATCHING: "https://{}:5492",
    dccommon_consts.ENDPOINT_TYPE_FM: "https://{}:18003",
    dccommon_consts.ENDPOINT_TYPE_NFV: "https://{}:4546"
}


class SubcloudManager(manager.Manager):
    """Manages tasks related to subclouds."""

    regionone_data = collections.defaultdict(dict)

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SubcloudManager initialization...'))

        super(SubcloudManager, self).__init__(service_name="subcloud_manager",
                                              *args, **kwargs)
        self.context = dcmanager_context.get_admin_context()
        self.dcorch_rpc_client = dcorch_rpc_client.EngineClient()
        self.fm_api = fm_api.FaultAPIs()
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()
        self.state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()

    @staticmethod
    def _get_subcloud_cert_name(subcloud_name):
        cert_name = "%s-adminep-ca-certificate" % subcloud_name
        return cert_name

    @staticmethod
    def _get_subcloud_cert_secret_name(subcloud_name):
        secret_name = "%s-adminep-ca-certificate" % subcloud_name
        return secret_name

    @staticmethod
    def _create_intermediate_ca_cert(payload):
        subcloud_name = payload["name"]
        cert_name = SubcloudManager._get_subcloud_cert_name(subcloud_name)
        secret_name = SubcloudManager._get_subcloud_cert_secret_name(
            subcloud_name)

        cert = {
            "apiVersion": "%s/%s" % (kubeoperator.CERT_MANAGER_GROUP,
                                     kubeoperator.CERT_MANAGER_VERSION),
            "kind": "Certificate",
            "metadata": {
                "namespace": CERT_NAMESPACE,
                "name": cert_name
            },
            "spec": {
                "secretName": secret_name,
                "duration": SC_INTERMEDIATE_CERT_DURATION,
                "renewBefore": SC_INTERMEDIATE_CERT_RENEW_BEFORE,
                "issuerRef": {
                    "kind": "Issuer",
                    "name": "dc-adminep-root-ca-issuer"
                },
                "commonName": cert_name,
                "isCA": True,
            },
        }

        kube = kubeoperator.KubeOperator()
        kube.apply_cert_manager_certificate(CERT_NAMESPACE, cert_name, cert)

        for count in range(1, 20):
            secret = kube.kube_get_secret(secret_name, CERT_NAMESPACE)
            if not hasattr(secret, 'data'):
                time.sleep(1)
                LOG.debug('Wait for %s ... %s' % (secret_name, count))
                continue

            data = secret.data
            if ('ca.crt' not in data or
                    'tls.crt' not in data or 'tls.key' not in data) or  \
               not (data['ca.crt'] and data['tls.crt'] and data['tls.key']):
                # ca cert, certificate and key pair are needed and must exist
                # for creating an intermediate ca. If not, certificate is not
                # ready yet.
                time.sleep(1)
                LOG.debug('Wait for %s ... %s' % (secret_name, count))
                continue

            payload['dc_root_ca_cert'] = data['ca.crt']
            payload['sc_ca_cert'] = data['tls.crt']
            payload['sc_ca_key'] = data['tls.key']
            return

        raise Exception("Secret for certificate %s is not ready." % cert_name)

    # TODO(kmacleod) switch to using utils.get_ansible_filename
    @staticmethod
    def _get_ansible_filename(subcloud_name, postfix='.yml'):
        ansible_filename = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH,
            subcloud_name + postfix)
        return ansible_filename

    def compose_install_command(self, subcloud_name,
                                ansible_subcloud_inventory_file,
                                software_version=None):
        install_command = [
            "ansible-playbook", dccommon_consts.ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "@%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH + "/" +
                  subcloud_name + '/' + "install_values.yml",
            "-e", "install_release_version=%s" %
                  software_version if software_version else SW_VERSION]
        return install_command

    def compose_bootstrap_command(self, subcloud_name,
                                  ansible_subcloud_inventory_file,
                                  software_version=None):
        bootstrap_command = [
            "ansible-playbook",
            utils.get_playbook_for_software_version(
                ANSIBLE_SUBCLOUD_PLAYBOOK, software_version),
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name
        ]
        # Add the overrides dir and region_name so the playbook knows
        # which overrides to load
        bootstrap_command += [
            "-e", str("override_files_dir='%s' region_name=%s") % (
                dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name),
            "-e", "install_release_version=%s" %
                  software_version if software_version else SW_VERSION]
        return bootstrap_command

    def compose_config_command(self, subcloud_name, ansible_subcloud_inventory_file, payload):
        config_command = [
            "ansible-playbook", payload[consts.DEPLOY_PLAYBOOK],
            "-e", "@%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH + "/" +
                  subcloud_name + '_deploy_values.yml',
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name
            ]
        return config_command

    def compose_backup_command(self, subcloud_name, ansible_subcloud_inventory_file):
        backup_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_BACKUP_CREATE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "subcloud_bnr_overrides=%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH + "/" +
            subcloud_name + "_backup_create_values.yml"]

        return backup_command

    def compose_backup_delete_command(self, subcloud_name,
                                      ansible_subcloud_inventory_file):
        backup_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_BACKUP_DELETE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "subcloud_bnr_overrides=%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH + "/" +
            subcloud_name + "_backup_delete_values.yml"]

        return backup_command

    def compose_backup_restore_command(self, subcloud_name, ansible_subcloud_inventory_file):
        backup_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_BACKUP_RESTORE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "subcloud_bnr_overrides=%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH + "/" +
            subcloud_name + "_backup_restore_values.yml"]

        return backup_command

    def compose_update_command(self, subcloud_name, ansible_subcloud_inventory_file):
        subcloud_update_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_UPDATE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "--timeout", UPDATE_PLAYBOOK_TIMEOUT,
            "-e", "subcloud_update_overrides=%s" % dccommon_consts.ANSIBLE_OVERRIDES_PATH + "/" +
            subcloud_name + "_update_values.yml"]
        return subcloud_update_command

    def compose_rehome_command(self, subcloud_name,
                               ansible_subcloud_inventory_file,
                               software_version):
        rehome_command = [
            "ansible-playbook",
            utils.get_playbook_for_software_version(
                ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK, software_version),
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "--timeout", REHOME_PLAYBOOK_TIMEOUT,
            "-e", str("override_files_dir='%s' region_name=%s") % (
                dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name)]
        return rehome_command

    def rehome_subcloud(self, context, subcloud, payload):
        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX)

        rehome_command = self.compose_rehome_command(
            subcloud.name,
            ansible_subcloud_inventory_file,
            subcloud.software_version)

        self.run_deploy_thread(subcloud, payload, context,
                               rehome_command=rehome_command)

    def add_subcloud(self, context, subcloud_id, payload):
        """Add subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: id of the subcloud
        :param payload: subcloud configuration
        """
        LOG.info(f"Adding subcloud {payload['name']}.")

        rehoming = payload.get('migrate', '').lower() == "true"
        payload['ansible_ssh_pass'] = payload['sysadmin_password']

        # Create the subcloud
        subcloud = self.subcloud_deploy_create(context, subcloud_id,
                                               payload, rehoming,
                                               return_as_dict=False)

        # Return if create failed
        if rehoming:
            success_state = consts.DEPLOY_STATE_PRE_REHOME
        else:
            success_state = consts.DEPLOY_STATE_CREATED
        if subcloud.deploy_status != success_state:
            return

        # Rehome subcloud
        if rehoming:
            self.rehome_subcloud(context, subcloud, payload)
            return

        # Define which deploy phases should be run
        phases_to_run = []
        if consts.INSTALL_VALUES in payload:
            phases_to_run.append(consts.DEPLOY_PHASE_INSTALL)
        phases_to_run.append(consts.DEPLOY_PHASE_BOOTSTRAP)
        if consts.DEPLOY_CONFIG in payload:
            phases_to_run.append(consts.DEPLOY_PHASE_CONFIG)

        # Finish adding the subcloud by running the deploy phases
        succeeded = self.run_deploy_phases(
            context, subcloud_id, payload, phases_to_run)

        if succeeded:
            subcloud = db_api.subcloud_update(
                context, subcloud_id, deploy_status=consts.DEPLOY_STATE_DONE)

        LOG.info(f"Finished adding subcloud {subcloud['name']}.")

    def reconfigure_subcloud(self, context, subcloud_id, payload):
        """Reconfigure subcloud

        :param context: request context object
        :param subcloud_id: id of the subcloud
        :param payload: subcloud configuration
        """
        LOG.info("Reconfiguring subcloud %s." % subcloud_id)

        subcloud = db_api.subcloud_update(
            context, subcloud_id,
            deploy_status=consts.DEPLOY_STATE_PRE_DEPLOY)
        try:
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            config_command = None
            if "deploy_playbook" in payload:
                self._prepare_for_deployment(payload, subcloud.name)
                config_command = self.compose_config_command(
                    subcloud.name,
                    ansible_subcloud_inventory_file,
                    payload)

            del payload['sysadmin_password']
            apply_thread = threading.Thread(
                target=self.run_deploy_thread,
                args=(subcloud, payload, context, None, None, config_command))
            apply_thread.start()
            return db_api.subcloud_db_model_to_dict(subcloud)
        except Exception:
            LOG.exception("Failed to create subcloud %s" % subcloud.name)
            # If we failed to create the subcloud, update the
            # deployment status
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_DEPLOY_PREP_FAILED)

    def reinstall_subcloud(self, context, subcloud_id, payload):
        """Reinstall subcloud

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: subcloud reinstall
        """

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)

        LOG.info("Reinstalling subcloud %s." % subcloud_id)

        try:
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            m_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            cached_regionone_data = self._get_cached_regionone_data(m_ks_client)
            self._populate_payload_with_cached_keystone_data(
                cached_regionone_data, payload)

            payload['install_values']['ansible_ssh_pass'] = \
                payload['sysadmin_password']
            payload['install_values']['ansible_become_pass'] = \
                payload['sysadmin_password']
            payload['bootstrap-address'] = \
                payload['install_values']['bootstrap_address']

            config_command = None
            if "deploy_playbook" in payload:
                self._prepare_for_deployment(payload, subcloud.name)
                config_command = self.compose_config_command(
                    subcloud.name,
                    ansible_subcloud_inventory_file,
                    payload)
            del payload['sysadmin_password']

            payload['users'] = dict()
            for user in USERS_TO_REPLICATE:
                payload['users'][user] = \
                    str(keyring.get_password(
                        user, dccommon_consts.SERVICES_USER_NAME))

            utils.create_subcloud_inventory(payload,
                                            ansible_subcloud_inventory_file)

            self._create_intermediate_ca_cert(payload)

            self._write_subcloud_ansible_config(cached_regionone_data, payload)

            install_command = self.compose_install_command(
                subcloud.name,
                ansible_subcloud_inventory_file,
                payload['software_version'])
            bootstrap_command = self.compose_bootstrap_command(
                subcloud.name,
                ansible_subcloud_inventory_file,
                payload['software_version'])
            network_reconfig = utils.has_network_reconfig(payload, subcloud)
            apply_thread = threading.Thread(
                target=self.run_deploy_thread,
                args=(subcloud, payload, context,
                      install_command, bootstrap_command, config_command,
                      None, network_reconfig))
            apply_thread.start()
            return db_api.subcloud_db_model_to_dict(subcloud)
        except Exception:
            LOG.exception("Failed to reinstall subcloud %s" % subcloud.name)
            # If we failed to reinstall the subcloud, update the
            # deployment status
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)

    def create_subcloud_backups(self, context, payload):
        """Backup subcloud or group of subclouds

        :param context: request context object
        :param payload: subcloud backup create detail
        """

        subcloud_id = payload.get('subcloud')
        group_id = payload.get('group')

        # Retrieve either a single subcloud or all subclouds in a group
        subclouds = [db_api.subcloud_get(context, subcloud_id)] if subcloud_id\
            else db_api.subcloud_get_for_group(context, group_id)

        self._filter_subclouds_with_ongoing_backup(subclouds)
        self._update_backup_status(context, subclouds,
                                   consts.BACKUP_STATE_INITIAL)

        # Validate the subclouds and filter the ones applicable for backup
        self._update_backup_status(context, subclouds,
                                   consts.BACKUP_STATE_VALIDATING)

        subclouds_to_backup, invalid_subclouds = \
            self._validate_subclouds_for_backup(subclouds, 'create')

        self._mark_invalid_subclouds_for_backup(context, invalid_subclouds)

        # Use thread pool to limit number of operations in parallel
        backup_pool = greenpool.GreenPool(size=MAX_PARALLEL_SUBCLOUD_BACKUP_CREATE)

        # Spawn threads to back up each applicable subcloud
        backup_function = functools.partial(self._backup_subcloud, context,
                                            payload)

        self._run_parallel_group_operation('backup create',
                                           backup_function,
                                           backup_pool,
                                           subclouds_to_backup)

        LOG.info("Subcloud backup operation finished")

    def delete_subcloud_backups(self, context, release_version, payload):
        """Delete backups for subcloud or group of subclouds for a given release

        :param context: request context object
        :param release_version Backup release version to be deleted
        :param payload: subcloud backup delete detail
        """

        local_delete = payload.get('local_only')

        subclouds_to_delete_backup, invalid_subclouds = \
            self._filter_subclouds_for_backup_delete(context, payload, local_delete)

        # Spawn threads to back up each applicable subcloud
        backup_delete_function = functools.partial(
            self._delete_subcloud_backup, context, payload, release_version)

        # Use thread pool to limit number of operations in parallel
        max_parallel_operations = MAX_PARALLEL_SUBCLOUD_BACKUP_DELETE
        backup_delete_pool = greenpool.GreenPool(size=max_parallel_operations)

        failed_subclouds = self._run_parallel_group_operation(
            'backup delete', backup_delete_function, backup_delete_pool,
            subclouds_to_delete_backup)

        LOG.info("Subcloud backup delete operation finished")

        return self._subcloud_operation_notice('delete', subclouds_to_delete_backup,
                                               failed_subclouds, invalid_subclouds)

    def restore_subcloud_backups(self, context, payload):
        """Restore a subcloud or group of subclouds from backup data

        :param context: request context object
        :param payload: restore backup subcloud detail
        """

        subcloud_id = payload.get('subcloud')
        group_id = payload.get('group')

        # Initialize subclouds lists
        restore_subclouds, invalid_subclouds, failed_subclouds = (
            list(), list(), list())

        # Retrieve either a single subcloud or all subclouds in a group
        subclouds = (
            [db_api.subcloud_get(context, subcloud_id)] if subcloud_id
            else db_api.subcloud_get_for_group(context, group_id)
        )

        restore_subclouds, invalid_subclouds = (
            self._validate_subclouds_for_backup(subclouds, 'restore')
        )

        if restore_subclouds:
            # Use thread pool to limit number of operations in parallel
            restore_pool = greenpool.GreenPool(
                size=MAX_PARALLEL_SUBCLOUD_BACKUP_RESTORE)

            # Spawn threads to back up each applicable subcloud
            restore_function = functools.partial(
                self._restore_subcloud_backup, context, payload)

            failed_subclouds = self._run_parallel_group_operation(
                'backup restore', restore_function,
                restore_pool, restore_subclouds
            )

        restored_subclouds = len(restore_subclouds) - len(failed_subclouds)
        LOG.info("Subcloud restore backup operation finished.\n"
                 "Restored subclouds: %s. Invalid subclouds: %s. "
                 "Failed subclouds: %s." % (restored_subclouds,
                                            len(invalid_subclouds),
                                            len(failed_subclouds)))

        return self._subcloud_operation_notice('restore', restore_subclouds,
                                               failed_subclouds, invalid_subclouds)

    def _deploy_bootstrap_prep(self, context, subcloud, payload: dict,
                               ansible_subcloud_inventory_file):
        """Run the preparation steps needed to run the bootstrap operation

        :param context: target request context object
        :param subcloud: subcloud model object
        :param payload: bootstrap request parameters
        :param ansible_subcloud_inventory_file: the ansible inventory file path
        :return: ansible command needed to run the bootstrap playbook
        """
        management_subnet = utils.get_management_subnet(payload)
        sys_controller_gw_ip = payload.get(
            "systemcontroller_gateway_address")

        if (management_subnet != subcloud.management_subnet) or (
                sys_controller_gw_ip != subcloud.systemcontroller_gateway_ip):
            m_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            # Create a new route
            self._create_subcloud_route(payload, m_ks_client,
                                        sys_controller_gw_ip)
            # Delete previous route
            self._delete_subcloud_routes(m_ks_client, subcloud)
            # Update endpoints
            self._update_services_endpoint(context, payload, subcloud.name,
                                           m_ks_client)

        # Update subcloud
        subcloud = db_api.subcloud_update(
            context,
            subcloud.id,
            description=payload.get("description", None),
            management_subnet=utils.get_management_subnet(payload),
            management_gateway_ip=utils.get_management_gateway_address(
                payload),
            management_start_ip=utils.get_management_start_address(
                payload),
            management_end_ip=utils.get_management_end_address(payload),
            systemcontroller_gateway_ip=payload.get(
                "systemcontroller_gateway_address", None),
            location=payload.get("location", None),
            deploy_status=consts.DEPLOY_STATE_PRE_BOOTSTRAP)

        # Populate payload with passwords
        payload['ansible_become_pass'] = payload['sysadmin_password']
        payload['ansible_ssh_pass'] = payload['sysadmin_password']
        payload['admin_password'] = str(keyring.get_password('CGCS', 'admin'))
        payload_without_sysadmin_password = payload.copy()
        if 'sysadmin_password' in payload_without_sysadmin_password:
            del payload_without_sysadmin_password['sysadmin_password']

        # Update the ansible overrides file
        overrides_file = os.path.join(dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                                      subcloud.name + '.yml')
        utils.update_values_on_yaml_file(overrides_file,
                                         payload_without_sysadmin_password)

        # Update the ansible inventory for the subcloud
        utils.create_subcloud_inventory(payload,
                                        ansible_subcloud_inventory_file)

        bootstrap_command = self.compose_bootstrap_command(
            subcloud.name,
            ansible_subcloud_inventory_file,
            subcloud.software_version)
        return bootstrap_command

    def _deploy_config_prep(self, subcloud, payload: dict,
                            ansible_subcloud_inventory_file):
        """Run the preparation steps needed to run the config operation

        :param subcloud: target subcloud model object
        :param payload: config request parameters
        :param ansible_subcloud_inventory_file: the ansible inventory file path
        :return: ansible command needed to run the config playbook
        """
        self._prepare_for_deployment(payload, subcloud.name)
        config_command = self.compose_config_command(
            subcloud.name,
            ansible_subcloud_inventory_file,
            payload)
        return config_command

    def _deploy_install_prep(self, subcloud, payload: dict,
                             ansible_subcloud_inventory_file):
        """Run the preparation steps needed to run the install operation

        :param subcloud: target subcloud model object
        :param payload: install request parameters
        :param ansible_subcloud_inventory_file: the ansible inventory file path
        :return: ansible command needed to run the install playbook
        """
        payload['install_values']['ansible_ssh_pass'] = \
            payload['sysadmin_password']
        payload['install_values']['ansible_become_pass'] = \
            payload['sysadmin_password']

        # If all update_values already exists on override file or are
        # the same as the existing ones, the update won't happen
        # and the file will remain untouched
        bootstrap_file = psd_common.get_config_file_path(subcloud.name,
                                                         consts.BOOTSTRAP_VALUES)
        update_values = {'software_version': payload['software_version'],
                         'bmc_password': payload['bmc_password'],
                         'ansible_ssh_pass': payload['sysadmin_password'],
                         'ansible_become_pass': payload['sysadmin_password']
                         }
        utils.update_values_on_yaml_file(bootstrap_file,
                                         update_values)

        install_command = self.compose_install_command(
            subcloud.name,
            ansible_subcloud_inventory_file,
            payload['software_version'])

        return install_command

    def subcloud_deploy_abort(self, context, subcloud_id, deploy_status):
        """Abort the subcloud deploy

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param deploy_status: subcloud deploy status from db
        """

        LOG.info("Aborting deployment of subcloud %s." % subcloud_id)
        subcloud = utils.update_abort_status(context, subcloud_id, deploy_status)

        try:
            run_ansible = RunAnsible()
            aborted = run_ansible.run_abort(subcloud.name)
            if not aborted:
                LOG.warning("Ansible deploy phase subprocess of %s "
                            "was terminated before it could be aborted"
                            % subcloud.name)
                # let the main phase thread handle the state update
                return

            if subcloud.deploy_status == consts.DEPLOY_STATE_ABORTING_INSTALL:
                # First delete the k8s job and pod, stopping the current
                # installation attempt if exists
                # Then send shutdown signal to subcloud
                kube = kubeoperator.KubeOperator()
                shutdown_subcloud = SubcloudShutdown(subcloud.name)
                namespace = dccommon_consts.RVMC_NAME_PREFIX
                jobname = '%s-%s' % (namespace, subcloud.name)
                pod_basename = '%s-' % jobname
                all_pods = kube.get_pods_by_namespace(namespace)
                desired_pod = next((s for s in all_pods if pod_basename in s), None)
                if desired_pod:
                    kube.kube_delete_job(jobname, namespace)
                    kube.kube_delete_pod(desired_pod, namespace)
                    while kube.pod_exists(desired_pod, namespace):
                        time.sleep(2)
                shutdown_subcloud.send_shutdown_signal()
        except Exception as ex:
            LOG.error("Subcloud deploy abort failed for subcloud %s" % subcloud.name)
            utils.update_abort_status(context, subcloud.id, subcloud.deploy_status,
                                      abort_failed=True)
            # exception is logged above
            raise ex
        LOG.info("Successfully aborted deployment of %s" % subcloud.name)
        utils.update_abort_status(context, subcloud.id, subcloud.deploy_status)

    def subcloud_deploy_resume(self, context, subcloud_id, subcloud_name,
                               payload: dict, deploy_states_to_run):
        """Resume the subcloud deployment

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param subcloud_name: name of the subcloud
        :param payload: subcloud resume payload
        :param deploy_states_to_run: deploy phases pending execution
        """
        LOG.info("Resuming deployment of subcloud %s. Deploy phases to be executed: %s"
                 % (subcloud_name, ', '.join(deploy_states_to_run)))

        self.run_deploy_phases(context, subcloud_id, payload,
                               deploy_states_to_run)

    def subcloud_deploy_create(self, context, subcloud_id, payload,
                               rehoming=False, return_as_dict=True):
        """Create subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :param payload: subcloud configuration
        :param rehoming: flag indicating if this is part of a rehoming operation
        :param return_as_dict: converts the subcloud DB object to a dict before returning
        :return: resulting subcloud DB object or dictionary
        """
        LOG.info("Creating subcloud %s." % payload['name'])

        if rehoming:
            deploy_state = consts.DEPLOY_STATE_PRE_REHOME
        else:
            deploy_state = consts.DEPLOY_STATE_CREATING

        subcloud = db_api.subcloud_update(
            context, subcloud_id,
            deploy_status=deploy_state)

        try:
            # Create a new route to this subcloud on the management interface
            # on both controllers.
            m_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            subcloud_subnet = netaddr.IPNetwork(
                utils.get_management_subnet(payload))
            endpoint = m_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(dccommon_consts.DEFAULT_REGION_NAME,
                                         m_ks_client.session,
                                         endpoint=endpoint)
            LOG.debug("Getting cached regionone data for %s" % subcloud.name)
            cached_regionone_data = self._get_cached_regionone_data(
                m_ks_client, sysinv_client)
            for mgmt_if_uuid in cached_regionone_data['mgmt_interface_uuids']:
                sysinv_client.create_route(
                    mgmt_if_uuid,
                    str(subcloud_subnet.ip),
                    subcloud_subnet.prefixlen,
                    payload['systemcontroller_gateway_address'],
                    1)

            # Create endpoints to this subcloud on the
            # management-start-ip of the subcloud which will be allocated
            # as the floating Management IP of the Subcloud if the
            # Address Pool is not shared. Incase the endpoint entries
            # are incorrect, or the management IP of the subcloud is changed
            # in the future, it will not go managed or will show up as
            # out of sync. To fix this use Openstack endpoint commands
            # on the SystemController to change the subcloud endpoints.
            # The non-identity endpoints are added to facilitate horizon access
            # from the System Controller to the subcloud.
            endpoint_config = []
            endpoint_ip = utils.get_management_start_address(payload)
            if netaddr.IPAddress(endpoint_ip).version == 6:
                endpoint_ip = '[' + endpoint_ip + ']'

            for service in m_ks_client.services_list:
                admin_endpoint_url = ENDPOINT_URLS.get(service.type, None)
                if admin_endpoint_url:
                    admin_endpoint_url = admin_endpoint_url.format(endpoint_ip)
                    endpoint_config.append(
                        {"id": service.id,
                         "admin_endpoint_url": admin_endpoint_url})

            if len(endpoint_config) < len(ENDPOINT_URLS):
                raise exceptions.BadRequest(
                    resource='subcloud',
                    msg='Missing service in SystemController')

            for endpoint in endpoint_config:
                try:
                    m_ks_client.keystone_client.endpoints.create(
                        endpoint["id"],
                        endpoint['admin_endpoint_url'],
                        interface=dccommon_consts.KS_ENDPOINT_ADMIN,
                        region=subcloud.name)
                except Exception as e:
                    # Keystone service must be temporarily busy, retry
                    LOG.error(str(e))
                    m_ks_client.keystone_client.endpoints.create(
                        endpoint["id"],
                        endpoint['admin_endpoint_url'],
                        interface=dccommon_consts.KS_ENDPOINT_ADMIN,
                        region=subcloud.name)

            # Inform orchestrator that subcloud has been added
            self.dcorch_rpc_client.add_subcloud(
                context, subcloud.name, subcloud.software_version)

            # create entry into alarm summary table, will get real values later
            alarm_updates = {'critical_alarms': -1,
                             'major_alarms': -1,
                             'minor_alarms': -1,
                             'warnings': -1,
                             'cloud_status': consts.ALARMS_DISABLED}
            db_api.subcloud_alarms_create(context, subcloud.name,
                                          alarm_updates)

            # Regenerate the addn_hosts_dc file
            self._create_addn_hosts_dc(context)

            self._populate_payload_with_cached_keystone_data(
                cached_regionone_data, payload, populate_passwords=False)

            if "deploy_playbook" in payload:
                self._prepare_for_deployment(payload, subcloud.name,
                                             populate_passwords=False)

            payload['users'] = {}
            for user in USERS_TO_REPLICATE:
                payload['users'][user] = \
                    str(keyring.get_password(
                        user, dccommon_consts.SERVICES_USER_NAME))

            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = utils.get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            # Create the ansible inventory for the new subcloud
            utils.create_subcloud_inventory(payload,
                                            ansible_subcloud_inventory_file)

            # create subcloud intermediate certificate and pass in keys
            self._create_intermediate_ca_cert(payload)

            # Write this subclouds overrides to file
            # NOTE: This file should not be deleted if subcloud add fails
            # as it is used for debugging
            self._write_subcloud_ansible_config(cached_regionone_data, payload)

            if not rehoming:
                deploy_state = consts.DEPLOY_STATE_CREATED

        except Exception:
            LOG.exception("Failed to create subcloud %s" % payload['name'])
            # If we failed to create the subcloud, update the deployment status

            if rehoming:
                deploy_state = consts.DEPLOY_STATE_REHOME_PREP_FAILED
            else:
                deploy_state = consts.DEPLOY_STATE_CREATE_FAILED

        subcloud = db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=deploy_state)

        # The RPC call must return the subcloud as a dictionary, otherwise it
        # should return the DB object for dcmanager internal use (subcloud add,
        # resume and redeploy)
        if return_as_dict:
            subcloud = db_api.subcloud_db_model_to_dict(subcloud)

        return subcloud

    def subcloud_deploy_install(self, context, subcloud_id, payload: dict) -> bool:
        """Install subcloud

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: subcloud Install
        :return: success status
        """

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            software_version=payload['software_version'],
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
            data_install=json.dumps(payload['install_values']))

        LOG.info("Installing subcloud %s." % subcloud.name)

        try:
            log_file = (
                os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                + "_playbook_output.log"
            )
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            install_command = self._deploy_install_prep(
                subcloud, payload, ansible_subcloud_inventory_file)
            install_success = self._run_subcloud_install(
                context, subcloud, install_command,
                log_file, payload['install_values'],
                abortable=True)
            if install_success:
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_INSTALLED,
                    error_description=consts.ERROR_DESC_EMPTY)
            return install_success

        except Exception:
            LOG.exception("Failed to install subcloud %s" % subcloud.name)
            # If we failed to install the subcloud,
            # update the deployment status
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)
            return False

    def subcloud_deploy_bootstrap(self, context, subcloud_id, payload):
        """Bootstrap subcloud

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :param payload: subcloud bootstrap configuration
        :return: success status
        """
        LOG.info("Bootstrapping subcloud %s." % payload['name'])

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)

        try:
            log_file = (
                os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                + "_playbook_output.log"
            )
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            bootstrap_command = self._deploy_bootstrap_prep(
                context, subcloud, payload,
                ansible_subcloud_inventory_file)
            bootstrap_success = self._run_subcloud_bootstrap(
                context, subcloud, bootstrap_command, log_file)
            return bootstrap_success

        except Exception:
            LOG.exception("Failed to bootstrap subcloud %s" % payload['name'])
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED)
            return False

    def subcloud_deploy_config(self, context, subcloud_id, payload: dict) -> bool:
        """Configure subcloud

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :param payload: subcloud configuration
        :return: success status
        """
        LOG.info("Configuring subcloud %s." % subcloud_id)

        subcloud = db_api.subcloud_update(
            context, subcloud_id,
            deploy_status=consts.DEPLOY_STATE_PRE_CONFIG)
        try:
            log_file = (
                os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
                + "_playbook_output.log"
            )
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            self._prepare_for_deployment(payload, subcloud.name)
            config_command = self.compose_config_command(
                subcloud.name,
                ansible_subcloud_inventory_file,
                payload)

            config_success = self._run_subcloud_config(subcloud, context,
                                                       config_command, log_file)
            return config_success

        except Exception:
            LOG.exception("Failed to configure %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_CONFIG_FAILED)
            return False

    def subcloud_deploy_complete(self, context, subcloud_id):
        """Completes the subcloud deployment.

        :param context: request context object
        :param subcloud_id: subcloud_id from db
        :return: resulting subcloud dictionary
        """
        LOG.info("Completing subcloud %s deployment." % subcloud_id)

        # Just update the deploy status
        subcloud = db_api.subcloud_update(context, subcloud_id,
                                          deploy_status=consts.DEPLOY_STATE_DONE)

        LOG.info("Subcloud %s deploy status set to: %s"
                 % (subcloud_id, consts.DEPLOY_STATE_DONE))

        return db_api.subcloud_db_model_to_dict(subcloud)

    def _subcloud_operation_notice(
            self, operation, restore_subclouds, failed_subclouds,
            invalid_subclouds):
        all_failed = ((not set(restore_subclouds) - set(failed_subclouds))
                      and not invalid_subclouds)
        if all_failed:
            LOG.error("Backup %s failed for all applied subclouds" % operation)
            raise exceptions.SubcloudBackupOperationFailed(operation=operation)

        if invalid_subclouds:
            self._warn_for_invalid_subclouds_on_backup_operation(invalid_subclouds)
        if failed_subclouds:
            self._warn_for_failed_subclouds_on_backup_operation(operation,
                                                                failed_subclouds)

        if invalid_subclouds or failed_subclouds:
            return self._build_subcloud_operation_notice(operation,
                                                         failed_subclouds,
                                                         invalid_subclouds)
        return

    def _filter_subclouds_with_ongoing_backup(self, subclouds):
        i = 0
        while i < len(subclouds):
            subcloud = subclouds[i]
            if subcloud.backup_status in consts.STATES_FOR_ONGOING_BACKUP:
                LOG.info(_('Subcloud %s already has a backup operation in '
                           'progress' % subcloud.name))
                subclouds.pop(i)
            else:
                i += 1

    def _validate_subclouds_for_backup(self, subclouds, operation):
        valid_subclouds = []
        invalid_subclouds = []
        for subcloud in subclouds:
            is_valid = False
            try:
                if utils.is_valid_for_backup_operation(operation, subcloud):
                    is_valid = True

            except exceptions.ValidateFail:
                is_valid = False

            if is_valid:
                valid_subclouds.append(subcloud)
            else:
                invalid_subclouds.append(subcloud)

        return valid_subclouds, invalid_subclouds

    @staticmethod
    def _mark_invalid_subclouds_for_backup(context, invalid_subclouds):
        try:
            invalid_ids = {subcloud.id for subcloud in invalid_subclouds}
            invalid_names = {subcloud.name for subcloud in invalid_subclouds}

            if invalid_ids:
                # Set state on subclouds that failed validation
                LOG.warn('The following subclouds are not online and/or managed '
                         'and/or in a valid deploy state, and will not be backed '
                         'up: %s', ', '.join(list(invalid_names)))
                SubcloudManager._update_backup_status_by_ids(
                    context, invalid_ids,
                    consts.BACKUP_STATE_VALIDATE_FAILED)

        except DCManagerException as ex:
            LOG.exception("Subcloud backup validation failed")
            raise ex

    @staticmethod
    def _warn_for_invalid_subclouds_on_backup_operation(invalid_subclouds):
        invalid_names = {subcloud.name for subcloud in invalid_subclouds}
        LOG.warn('The following subclouds were not online and/or in a valid '
                 'deploy/management state, and thus were not be reached '
                 'for backup operation: %s', ', '.join(list(invalid_names)))

    @staticmethod
    def _warn_for_failed_subclouds_on_backup_operation(operation, failed_subclouds):
        failed_names = {subcloud.name for subcloud in failed_subclouds}
        LOG.warn('Backup %s operation failed for some subclouds, '
                 'check previous logs for details. Failed subclouds: %s' %
                 (operation, ', '.join(list(failed_names))))

    @staticmethod
    def _update_backup_status(context, subclouds, backup_status):
        subcloud_ids = [subcloud.id for subcloud in subclouds]
        return SubcloudManager.\
            _update_backup_status_by_ids(context, subcloud_ids,
                                         backup_status)

    @staticmethod
    def _update_backup_status_by_ids(context, subcloud_ids, backup_status):
        validate_state_form = {
            Subcloud.backup_status.name: backup_status
        }
        db_api.subcloud_bulk_update_by_ids(context, subcloud_ids,
                                           validate_state_form)

    @staticmethod
    def _run_parallel_group_operation(op_type, op_function, thread_pool, subclouds):
        failed_subclouds = []
        processed = 0

        for subcloud, success in thread_pool.imap(op_function, subclouds):
            processed += 1

            if not success:
                failed_subclouds.append(subcloud)

            completion = float(processed) / float(len(subclouds)) * 100
            remaining = len(subclouds) - processed
            LOG.info("Processed subcloud %s for %s (operation %.0f%% "
                     "complete, %d subcloud(s) remaining)" %
                     (subcloud.name, op_type, completion, remaining))

        return failed_subclouds

    def _backup_subcloud(self, context, payload, subcloud):
        try:
            # Health check validation
            if not utils.is_subcloud_healthy(subcloud.name):
                db_api.subcloud_update(
                    context,
                    subcloud.id,
                    backup_status=consts.BACKUP_STATE_VALIDATE_FAILED,
                )
                LOG.info(
                    ("Subcloud %s is not in good health for subcloud-backup create")
                    % subcloud.name
                )
                return subcloud, False

            db_api.subcloud_update(
                context,
                subcloud.id,
                backup_status=consts.BACKUP_STATE_PRE_BACKUP,
            )

            subcloud_inventory_file = self._create_subcloud_inventory_file(subcloud)

            # Prepare for backup
            overrides_file = self._create_overrides_for_backup_or_restore(
                'create', payload, subcloud.name
            )
            backup_command = self.compose_backup_command(
                subcloud.name, subcloud_inventory_file)

            self._clear_subcloud_backup_failure_alarm_if_exists(subcloud)
        except Exception:
            self._fail_subcloud_backup_prep(context, subcloud)
            return subcloud, False

        local_only = payload.get('local_only') or False
        success = self._run_subcloud_backup_create_playbook(
            subcloud, backup_command, context, local_only)

        if success:
            utils.delete_subcloud_inventory(overrides_file)

        return subcloud, success

    def _filter_subclouds_for_backup_delete(self, context, payload, local_delete):
        subcloud_id = payload.get('subcloud')
        group_id = payload.get('group')

        # Retrieve either a single subcloud or all subclouds in a group
        subclouds = [db_api.subcloud_get(context, subcloud_id)] if subcloud_id \
            else db_api.subcloud_get_for_group(context, group_id)
        invalid_subclouds = []

        # Subcloud state validation only required for local delete
        if local_delete:
            # Use same criteria defined for subcloud backup create
            subclouds_to_delete_backup, invalid_subclouds = \
                self._validate_subclouds_for_backup(subclouds, 'delete')
        else:
            # Otherwise, validation is unnecessary, since connection is not required
            subclouds_to_delete_backup = subclouds

        return subclouds_to_delete_backup, invalid_subclouds

    def _delete_subcloud_backup(self, context, payload, release_version, subcloud):
        try:
            overrides_file = self._create_overrides_for_backup_delete(
                payload, subcloud.name, release_version
            )
            inventory_file = self._create_subcloud_inventory_file(subcloud)
            delete_command = self.compose_backup_delete_command(
                subcloud.name, inventory_file)

        except Exception:
            LOG.exception("Failed to prepare subcloud %s for backup delete"
                          % subcloud.name)
            return subcloud, False

        success = self._run_subcloud_backup_delete_playbook(context, subcloud,
                                                            delete_command)

        if success:
            utils.delete_subcloud_inventory(overrides_file)

        return subcloud, success

    def _restore_subcloud_backup(self, context, payload, subcloud):
        log_file = (os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name) +
                    '_playbook_output.log')
        data_install = json.loads(subcloud.data_install)
        try:
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_RESTORE
            )
            subcloud_inventory_file = self._create_subcloud_inventory_file(
                subcloud, data_install=data_install)
            # Prepare for restore
            overrides_file = self._create_overrides_for_backup_or_restore(
                'restore', payload, subcloud.name
            )
            restore_command = self.compose_backup_restore_command(
                subcloud.name, subcloud_inventory_file)
        except Exception:
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_RESTORE_PREP_FAILED
            )
            LOG.exception("Failed to prepare subcloud %s for backup restore"
                          % subcloud.name)
            return subcloud, False

        if payload.get('with_install'):
            software_version = payload.get('software_version')
            install_command = self.compose_install_command(
                subcloud.name, subcloud_inventory_file, software_version)
            # Update data_install with missing data
            matching_iso, _ = utils.get_vault_load_files(software_version)
            data_install['software_version'] = software_version
            data_install['image'] = matching_iso
            data_install['ansible_ssh_pass'] = payload['sysadmin_password']
            data_install['ansible_become_pass'] = payload['sysadmin_password']
            install_success = self._run_subcloud_install(
                context, subcloud, install_command, log_file, data_install)
            if not install_success:
                return subcloud, False

        success = self._run_subcloud_backup_restore_playbook(
            subcloud, restore_command, context, log_file)

        if success:
            utils.delete_subcloud_inventory(overrides_file)

        return subcloud, success

    @staticmethod
    def _build_subcloud_operation_notice(operation, failed_subclouds, invalid_subclouds):
        invalid_subcloud_names = [subcloud.name for subcloud in invalid_subclouds]
        failed_subcloud_names = [subcloud.name for subcloud in failed_subclouds]

        notice = "Subcloud backup %s operation completed with warnings:\n" % operation
        if invalid_subclouds:
            notice += ("The following subclouds were skipped for local backup "
                       "%s operation: %s."
                       % (operation, ' ,'.join(invalid_subcloud_names)))
        if failed_subclouds:
            notice += ("The following subclouds failed during backup "
                       "%s operation: %s."
                       % (operation, ' ,'.join(failed_subcloud_names)))
        return notice

    def _create_subcloud_inventory_file(self, subcloud, data_install=None):
        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX)

        oam_fip = None
        # Restore is restrict to Redfish enabled subclouds
        if data_install:
            oam_fip = data_install.get('bootstrap_address')
        else:
            # Use subcloud floating IP for host reachability
            keystone_client = OpenStackDriver(
                region_name=subcloud.name,
                region_clients=None).keystone_client
            oam_fip = utils.get_oam_addresses(subcloud.name, keystone_client)\
                .oam_floating_ip

        # Add parameters used to generate inventory
        subcloud_params = {'name': subcloud.name,
                           'bootstrap-address': oam_fip}

        utils.create_subcloud_inventory(subcloud_params,
                                        ansible_subcloud_inventory_file)
        return ansible_subcloud_inventory_file

    def _create_overrides_for_backup_or_restore(self, op, payload, subcloud_name):
        # Set override names as expected by the playbook
        if not payload.get('override_values'):
            payload['override_values'] = {}

        payload['override_values']['local'] = \
            payload['local_only'] or False

        if op == 'create':
            payload['override_values']['backup_registry_images'] = \
                payload['registry_images'] or False
            suffix = 'backup_create_values'
        else:
            payload['override_values']['restore_registry_images'] = \
                payload['registry_images'] or False
            suffix = 'backup_restore_values'

        if not payload['local_only']:
            payload['override_values']['central_backup_dir'] = CENTRAL_BACKUP_DIR

        payload['override_values']['ansible_ssh_pass'] = \
            payload['sysadmin_password']
        payload['override_values']['ansible_become_pass'] = \
            payload['sysadmin_password']
        payload['override_values']['admin_password'] = \
            str(keyring.get_password('CGCS', 'admin'))

        if payload.get('backup_values'):
            LOG.info('Backup create: Received backup_values for subcloud %s'
                     % subcloud_name)
            for key, value in payload.get('backup_values').items():
                payload['override_values'][key] = value
        elif payload.get('restore_values'):
            LOG.info('Backup restore: Received restore_values for subcloud %s'
                     % subcloud_name)
            for key, value in payload.get('restore_values').items():
                payload['override_values'][key] = value

        return self._create_backup_overrides_file(payload, subcloud_name, suffix)

    def _create_overrides_for_backup_delete(self, payload, subcloud_name,
                                            release_version):
        # Set override names as expected by the playbook
        if not payload.get('override_values'):
            payload['override_values'] = {}

        payload['override_values']['software_version'] = release_version

        payload['override_values']['local'] = \
            payload['local_only'] or False

        if not payload['local_only']:
            payload['override_values']['central_backup_dir'] = CENTRAL_BACKUP_DIR
        else:
            payload['override_values']['ansible_ssh_pass'] = \
                payload['sysadmin_password']
            payload['override_values']['ansible_become_pass'] = \
                payload['sysadmin_password']

        return self._create_backup_overrides_file(
            payload, subcloud_name, 'backup_delete_values'
        )

    def _create_backup_overrides_file(self, payload, subcloud_name, filename_suffix):
        backup_overrides_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name + '_' +
            filename_suffix + '.yml')

        with open(backup_overrides_file, 'w') as f_out:
            f_out.write(
                '---\n'
            )
            for k, v in payload['override_values'].items():
                f_out.write("%s: %s\n" % (k, v))

        return backup_overrides_file

    def _run_subcloud_backup_create_playbook(self, subcloud, backup_command,
                                             context, local_only):
        log_file = os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name) + \
            '_playbook_output.log'

        db_api.subcloud_update(
            context, subcloud.id,
            backup_status=consts.BACKUP_STATE_IN_PROGRESS,
            error_description=consts.ERROR_DESC_EMPTY)

        # Run the subcloud backup playbook
        try:
            run_playbook(log_file, backup_command)

            # Decide between complete-local or complete-central
            if local_only:
                backup_status = consts.BACKUP_STATE_COMPLETE_LOCAL
            else:
                backup_status = consts.BACKUP_STATE_COMPLETE_CENTRAL

            db_api.subcloud_update(
                context, subcloud.id,
                backup_status=backup_status,
                backup_datetime=datetime.datetime.utcnow())

            LOG.info("Successfully backed up subcloud %s" % subcloud.name)
            return True
        except PlaybookExecutionFailed:
            self._fail_subcloud_backup_operation(context, log_file, subcloud)
            return False

    @staticmethod
    def _run_subcloud_backup_delete_playbook(context, subcloud, delete_command):
        log_file = os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name) + \
            '_playbook_output.log'

        try:
            # Run the subcloud backup delete playbook
            run_playbook(log_file, delete_command)

            # Set backup status to unknown after delete, since most recent backup may
            # have been deleted
            db_api.subcloud_bulk_update_by_ids(
                context, [subcloud.id],
                {Subcloud.backup_status.name: consts.BACKUP_STATE_UNKNOWN,
                 Subcloud.backup_datetime.name: None})

            LOG.info("Successfully deleted backup for subcloud %s" % subcloud.name)
            return True

        except PlaybookExecutionFailed:
            LOG.error("Failed to delete backup for subcloud %s, check individual "
                      "log at %s for detailed output." % (subcloud.name, log_file))

            msg = utils.find_ansible_error_msg(
                subcloud.name, log_file, consts.BACKUP_STATE_FAILED)
            LOG.error(msg)

            db_api.subcloud_update(
                context, subcloud.id,
                error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])

            return False

    def _run_subcloud_backup_restore_playbook(
            self, subcloud, restore_command, context, log_file):
        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_RESTORING,
            error_description=consts.ERROR_DESC_EMPTY
        )
        # Run the subcloud backup restore playbook
        try:
            run_playbook(log_file, restore_command)
            LOG.info("Successfully restore subcloud %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_DONE
            )
            return True
        except PlaybookExecutionFailed:
            msg = utils.find_ansible_error_msg(
                subcloud.name, log_file, consts.DEPLOY_STATE_RESTORING)
            LOG.error(msg)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_RESTORE_FAILED,
                error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH]
            )
            return False

    @staticmethod
    def _fail_subcloud_backup_prep(context, subcloud):
        LOG.exception("Failed to prepare subcloud %s for backup" % subcloud.name)

        db_api.subcloud_update(
            context, subcloud.id,
            backup_status=consts.BACKUP_STATE_PREP_FAILED)

    def _fail_subcloud_backup_operation(self, context, log_file, subcloud):
        msg = utils.find_ansible_error_msg(
            subcloud.name, log_file, consts.BACKUP_STATE_IN_PROGRESS)
        LOG.error(msg)

        db_api.subcloud_update(
            context, subcloud.id,
            backup_status=consts.BACKUP_STATE_FAILED,
            error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])

        self._set_subcloud_backup_failure_alarm(subcloud)

    def _clear_subcloud_backup_failure_alarm_if_exists(self, subcloud):
        entity_instance_id = "subcloud=%s" % subcloud.name

        try:
            fault = self.fm_api.get_fault(
                fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,
                entity_instance_id)
            if fault:
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,  # noqa
                    entity_instance_id)
        except Exception as e:
            LOG.exception(e)

    def _set_subcloud_backup_failure_alarm(self, subcloud):
        entity_instance_id = "subcloud=%s" % subcloud.name

        try:
            fault = fm_api.Fault(
                alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,  # noqa
                alarm_state=fm_const.FM_ALARM_STATE_SET,
                entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
                entity_instance_id=entity_instance_id,
                severity=fm_const.FM_ALARM_SEVERITY_MINOR,
                reason_text=("Subcloud Backup Failure (subcloud=%s)"
                             % subcloud.name),
                alarm_type=fm_const.FM_ALARM_TYPE_3,
                probable_cause=fm_const.ALARM_PROBABLE_CAUSE_UNKNOWN,
                proposed_repair_action="Retry subcloud backup after checking input "
                                       "file. If problem persists, please contact "
                                       "next level of support.",
                service_affecting=False)
            self.fm_api.set_fault(fault)
        except Exception as e:
            LOG.exception(e)

    def run_deploy_thread(self, subcloud, payload, context,
                          install_command=None, bootstrap_command=None,
                          config_command=None, rehome_command=None,
                          network_reconfig=None):
        try:
            self._run_deploy(subcloud, payload, context,
                             install_command, bootstrap_command,
                             config_command, rehome_command,
                             network_reconfig)
        except Exception as ex:
            LOG.exception("run_deploy failed")
            raise ex

    def _run_deploy(self, subcloud, payload, context,
                    install_command, bootstrap_command,
                    config_command, rehome_command,
                    network_reconfig):
        log_file = (
            os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name)
            + "_playbook_output.log"
        )
        if install_command:
            install_success = self._run_subcloud_install(
                context, subcloud, install_command,
                log_file, payload['install_values']
            )
            if not install_success:
                return
        if bootstrap_command:
            try:
                # Update the subcloud to bootstrapping
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING,
                    error_description=consts.ERROR_DESC_EMPTY)
            except Exception:
                LOG.error("DB subcloud_update failed")
                # exception is logged above
                raise

            # Run the ansible boostrap-subcloud playbook
            LOG.info("Starting bootstrap of %s" % subcloud.name)
            try:
                run_playbook(log_file, bootstrap_command)
            except PlaybookExecutionFailed:
                msg = utils.find_ansible_error_msg(
                    subcloud.name, log_file, consts.DEPLOY_STATE_BOOTSTRAPPING)
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                    error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])
                return
            LOG.info("Successfully bootstrapped %s" % subcloud.name)
        if config_command:
            # Run the custom deploy playbook
            LOG.info("Starting deploy of %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_DEPLOYING,
                error_description=consts.ERROR_DESC_EMPTY)

            try:
                run_playbook(log_file, config_command)
            except PlaybookExecutionFailed:
                msg = utils.find_ansible_error_msg(
                    subcloud.name, log_file, consts.DEPLOY_STATE_DEPLOYING)
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_DEPLOY_FAILED,
                    error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])
                return
            LOG.info("Successfully deployed %s" % subcloud.name)
        if rehome_command:
            # Update the deploy status to rehoming
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_REHOMING)

            # Run the rehome-subcloud playbook
            try:
                run_playbook(log_file, rehome_command)
            except PlaybookExecutionFailed:
                msg = "Failed to run the subcloud rehome playbook" \
                      " for subcloud %s, check individual log at " \
                      "%s for detailed output." % (
                          subcloud.name,
                          log_file)
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_REHOME_FAILED)
                return
            LOG.info("Successfully rehomed subcloud %s" %
                     subcloud.name)
        if network_reconfig:
            self._configure_system_controller_network(context, payload, subcloud)
            subcloud = db_api.subcloud_update(
                context,
                subcloud.id,
                description=payload.get('description', subcloud.description),
                management_subnet=utils.get_management_subnet(payload),
                management_gateway_ip=utils.get_management_gateway_address(payload),
                management_start_ip=utils.get_management_start_address(payload),
                management_end_ip=utils.get_management_end_address(payload),
                location=payload.get('location', subcloud.location),
                group_id=payload.get('group_id', subcloud.group_id),
                data_install=payload.get('data_install', subcloud.data_install)
            )

            # Regenerate the addn_hosts_dc file
            self._create_addn_hosts_dc(context)

        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            error_description=consts.ERROR_DESC_EMPTY)

    def run_deploy_phases(self, context, subcloud_id, payload,
                          deploy_phases_to_run):
        """Run one or more deployment phases, ensuring correct order

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: deploy phases payload
        :param deploy_phases_to_run: deploy phases that should run
        """
        try:
            succeeded = True
            if consts.DEPLOY_PHASE_INSTALL in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_install(
                    context, subcloud_id, payload)
            if succeeded and consts.DEPLOY_PHASE_BOOTSTRAP in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_bootstrap(
                    context, subcloud_id, payload)
            if succeeded and consts.DEPLOY_PHASE_CONFIG in deploy_phases_to_run:
                succeeded = self.subcloud_deploy_config(
                    context, subcloud_id, payload)
            return succeeded

        except Exception as ex:
            LOG.exception("run_deploy_phases failed")
            raise ex

    def _run_subcloud_config(self, subcloud, context,
                             config_command, log_file):
        # Run the custom deploy playbook
        LOG.info("Starting deploy of %s" % subcloud.name)
        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_CONFIGURING,
            error_description=consts.ERROR_DESC_EMPTY)

        try:
            run_ansible = RunAnsible()
            aborted = run_ansible.exec_playbook(
                log_file, config_command, subcloud.name)
        except PlaybookExecutionFailed:
            msg = utils.find_ansible_error_msg(
                subcloud.name, log_file, consts.DEPLOY_STATE_CONFIGURING)
            LOG.error(msg)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_CONFIG_FAILED,
                error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])
            return False
        if aborted:
            return False
        LOG.info("Successfully deployed %s" % subcloud.name)
        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            error_description=consts.ERROR_DESC_EMPTY)

    @staticmethod
    def _run_subcloud_install(context, subcloud, install_command,
                              log_file, payload, abortable=False):
        software_version = str(payload['software_version'])
        LOG.info("Preparing remote install of %s, version: %s",
                 subcloud.name, software_version)
        if (subcloud.deploy_status != consts.DEPLOY_STATE_PRE_INSTALL or
                subcloud.software_version != software_version):
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                software_version=software_version)
        try:
            install = SubcloudInstall(context, subcloud.name)
            install.prep(dccommon_consts.ANSIBLE_OVERRIDES_PATH, payload)
        except Exception as e:
            LOG.exception(e)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)
            LOG.error(str(e))
            install.cleanup(software_version)
            return False

        # Run the remote install playbook
        LOG.info("Starting remote install of %s" % subcloud.name)
        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_INSTALLING,
            error_description=consts.ERROR_DESC_EMPTY)
        try:
            aborted = install.install(
                consts.DC_ANSIBLE_LOG_DIR, install_command, abortable=abortable)
        except Exception as e:
            msg = utils.find_ansible_error_msg(
                subcloud.name, log_file, consts.DEPLOY_STATE_INSTALLING)
            LOG.error(str(e))
            LOG.error(msg)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED,
                error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])
            install.cleanup(software_version)
            return False
        install.cleanup(software_version)
        if aborted:
            return False
        LOG.info("Successfully installed %s" % subcloud.name)
        return True

    def _run_subcloud_bootstrap(self, context, subcloud,
                                bootstrap_command, log_file):
        # Update the subcloud deploy_status to bootstrapping
        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING,
            error_description=consts.ERROR_DESC_EMPTY)

        # Run the ansible subcloud boostrap playbook
        LOG.info("Starting bootstrap of %s" % subcloud.name)
        try:
            run_ansible = RunAnsible()
            aborted = run_ansible.exec_playbook(
                log_file, bootstrap_command, subcloud.name)
        except PlaybookExecutionFailed:
            msg = utils.find_ansible_error_msg(
                subcloud.name, log_file, consts.DEPLOY_STATE_BOOTSTRAPPING)
            LOG.error(msg)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH])
            return False

        if aborted:
            return False

        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPED,
            error_description=consts.ERROR_DESC_EMPTY)

        LOG.info("Successfully bootstrapped %s" % subcloud.name)
        return True

    def _create_addn_hosts_dc(self, context):
        """Generate the addn_hosts_dc file for hostname/ip translation"""

        addn_hosts_dc = os.path.join(CONFIG_PATH, ADDN_HOSTS_DC)
        addn_hosts_dc_temp = addn_hosts_dc + '.temp'

        subclouds = db_api.subcloud_get_all(context)
        with open(addn_hosts_dc_temp, 'w') as f_out_addn_dc_temp:
            for subcloud in subclouds:
                addn_dc_line = subcloud.management_start_ip + ' ' + \
                    subcloud.name + '\n'
                f_out_addn_dc_temp.write(addn_dc_line)

            # if no more subclouds, create empty file so dnsmasq does not
            # emit an error log.
            if not subclouds:
                f_out_addn_dc_temp.write(' ')

        if not filecmp.cmp(addn_hosts_dc_temp, addn_hosts_dc):
            os.rename(addn_hosts_dc_temp, addn_hosts_dc)
            # restart dnsmasq so it can re-read our addn_hosts file.
            os.system("pkill -HUP dnsmasq")

    def _write_subcloud_ansible_config(self, cached_regionone_data, payload):
        """Create the override file for usage with the specified subcloud"""

        overrides_file = os.path.join(dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                                      payload['name'] + '.yml')

        mgmt_pool = cached_regionone_data['mgmt_pool']
        mgmt_floating_ip = mgmt_pool.floating_address
        mgmt_subnet = "%s/%d" % (mgmt_pool.network, mgmt_pool.prefix)

        oam_addresses = cached_regionone_data['oam_addresses']
        oam_floating_ip = oam_addresses.oam_floating_ip
        oam_subnet = oam_addresses.oam_subnet

        with open(overrides_file, 'w') as f_out_overrides_file:
            f_out_overrides_file.write(
                '---'
                '\nregion_config: yes'
                '\ndistributed_cloud_role: subcloud'
                '\nsystem_controller_subnet: ' + mgmt_subnet +
                '\nsystem_controller_floating_address: ' + mgmt_floating_ip +
                '\nsystem_controller_oam_subnet: ' + oam_subnet +
                '\nsystem_controller_oam_floating_address: ' + oam_floating_ip
                + '\n'
            )

            for k, v in payload.items():
                if k not in ['deploy_playbook', 'deploy_values',
                             'deploy_config', 'deploy_chart',
                             'deploy_overrides', 'install_values']:
                    f_out_overrides_file.write("%s: %s\n" % (k, json.dumps(v)))

    def _write_deploy_files(self, payload, subcloud_name):
        """Create the deploy value files for the subcloud"""

        deploy_values_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name +
            '_deploy_values.yml')

        with open(deploy_values_file, 'w') as f_out_deploy_values_file:
            json.dump(payload['deploy_values'], f_out_deploy_values_file)

    def _prepare_for_deployment(self, payload, subcloud_name,
                                populate_passwords=True):
        payload['deploy_values'] = dict()
        if populate_passwords:
            payload['deploy_values']['ansible_become_pass'] = \
                payload['sysadmin_password']
            payload['deploy_values']['ansible_ssh_pass'] = \
                payload['sysadmin_password']
            payload['deploy_values']['admin_password'] = \
                str(keyring.get_password('CGCS', 'admin'))
        payload['deploy_values']['deployment_config'] = \
            payload[consts.DEPLOY_CONFIG]
        payload['deploy_values']['deployment_manager_chart'] = \
            payload[consts.DEPLOY_CHART]
        payload['deploy_values']['deployment_manager_overrides'] = \
            payload[consts.DEPLOY_OVERRIDES]
        self._write_deploy_files(payload, subcloud_name)

    def _delete_subcloud_routes(self, keystone_client, subcloud):
        """Delete the routes to this subcloud"""

        # Delete the route to this subcloud on the management interface on
        # both controllers.
        management_subnet = netaddr.IPNetwork(subcloud.management_subnet)
        endpoint = keystone_client.endpoint_cache.get_endpoint('sysinv')
        sysinv_client = SysinvClient(dccommon_consts.DEFAULT_REGION_NAME, keystone_client.session,
                                     endpoint=endpoint)
        cached_regionone_data = self._get_cached_regionone_data(keystone_client, sysinv_client)
        for mgmt_if_uuid in cached_regionone_data['mgmt_interface_uuids']:
            sysinv_client.delete_route(mgmt_if_uuid,
                                       str(management_subnet.ip),
                                       management_subnet.prefixlen,
                                       str(netaddr.IPAddress(subcloud.systemcontroller_gateway_ip)),
                                       1)

    @staticmethod
    def _delete_subcloud_cert(subcloud_name):
        cert_name = SubcloudManager._get_subcloud_cert_name(subcloud_name)
        secret_name = SubcloudManager._get_subcloud_cert_secret_name(
            subcloud_name)

        kube = kubeoperator.KubeOperator()
        kube.delete_cert_manager_certificate(CERT_NAMESPACE, cert_name)

        kube.kube_delete_secret(secret_name, CERT_NAMESPACE)
        LOG.info("cert %s and secret %s are deleted" % (cert_name, secret_name))

    def _remove_subcloud_details(self, context,
                                 subcloud,
                                 ansible_subcloud_inventory_file):
        """Remove subcloud details from database and inform orchestrators"""
        # Inform orchestrators that subcloud has been deleted
        try:
            self.dcorch_rpc_client.del_subcloud(context, subcloud.name)
        except RemoteError as e:
            # TODO(kmacleod): this should be caught as explicit remote exception
            # Fix when centos/python2 is no longer supported
            if "SubcloudNotFound" in str(e):
                pass

        # delete the associated alarm entry
        try:
            db_api.subcloud_alarms_delete(context, subcloud.name)
        except RemoteError as e:
            # TODO(kmacleod): fix same with above
            if "SubcloudNotFound" in str(e):
                pass

        # We only delete subcloud endpoints, region and user information
        # in the Central Region. The subcloud is already unmanaged and powered
        # down so is not accessible. Therefore set up a session with the
        # Central Region Keystone ONLY.
        keystone_client = OpenStackDriver(
            region_name=dccommon_consts.DEFAULT_REGION_NAME,
            region_clients=None).keystone_client

        # Delete keystone endpoints for subcloud
        keystone_client.delete_endpoints(subcloud.name)
        keystone_client.delete_region(subcloud.name)

        # Delete the routes to this subcloud
        self._delete_subcloud_routes(keystone_client, subcloud)

        # Remove the subcloud from the database
        try:
            db_api.subcloud_destroy(context, subcloud.id)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Delete the ansible inventory for the new subcloud
        utils.delete_subcloud_inventory(ansible_subcloud_inventory_file)

        # Delete the subcloud intermediate certificate
        SubcloudManager._delete_subcloud_cert(subcloud.name)

        # Delete the subcloud backup path
        self._delete_subcloud_backup_data(subcloud.name)

        # Regenerate the addn_hosts_dc file
        self._create_addn_hosts_dc(context)

    @staticmethod
    def _delete_subcloud_backup_data(subcloud_name):
        try:
            backup_path = os.path.join(CENTRAL_BACKUP_DIR, subcloud_name)
            if os.path.exists(backup_path):
                shutil.rmtree(backup_path)
        except Exception as e:
            LOG.exception(e)

    def delete_subcloud(self, context, subcloud_id):
        """Delete subcloud and notify orchestrators.

        :param context: request context object.
        :param subcloud_id: id of subcloud to delete
        """
        LOG.info("Deleting subcloud %s." % subcloud_id)

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)

        # Semantic checking
        if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
            raise exceptions.SubcloudNotUnmanaged()

        if subcloud.availability_status == \
                dccommon_consts.AVAILABILITY_ONLINE:
            raise exceptions.SubcloudNotOffline()

        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = self._get_ansible_filename(
            subcloud.name, INVENTORY_FILE_POSTFIX)

        self._remove_subcloud_details(context,
                                      subcloud,
                                      ansible_subcloud_inventory_file)

        # Clear any subcloud alarms.
        # Note that endpoint out-of-sync alarms should have been cleared when
        # the subcloud was unmanaged and the endpoint sync statuses were set to
        # unknown.
        #
        # TODO(kmacleod): Until an API is available to clear all alarms
        # for a subcloud, we manually clear the following:
        # - subcloud offline
        # - subloud resource out of sync
        # - Subcloud Backup Failure
        for alarm_id, entity_instance_id in (
                (fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                 "subcloud=%s" % subcloud.name),
                (fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                 "subcloud=%s.resource=%s" %
                 (subcloud.name, dccommon_consts.ENDPOINT_TYPE_DC_CERT)),
                (fm_const.FM_ALARM_ID_DC_SUBCLOUD_BACKUP_FAILED,
                 "subcloud=%s" % subcloud.name)):
            try:
                fault = self.fm_api.get_fault(alarm_id,
                                              entity_instance_id)
                if fault:
                    self.fm_api.clear_fault(alarm_id,
                                            entity_instance_id)
            except Exception as e:
                LOG.info(
                    "Problem clearing fault for subcloud %s, alarm_id=%s" %
                    (subcloud.name, alarm_id))
                LOG.exception(e)

    def update_subcloud(self,
                        context,
                        subcloud_id,
                        management_state=None,
                        description=None,
                        location=None,
                        group_id=None,
                        data_install=None,
                        force=None):
        """Update subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param management_state: new management state
        :param description: new description
        :param location: new location
        :param group_id: new subcloud group id
        :param data_install: subcloud install values
        :param force: force flag
        """

        LOG.info("Updating subcloud %s." % subcloud_id)

        # Get the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)
        original_management_state = subcloud.management_state

        # Semantic checking
        if management_state:
            if management_state == dccommon_consts.MANAGEMENT_UNMANAGED:
                if subcloud.management_state == dccommon_consts.MANAGEMENT_UNMANAGED:
                    LOG.warning("Subcloud %s already unmanaged" % subcloud_id)
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Subcloud is already unmanaged')
            elif management_state == dccommon_consts.MANAGEMENT_MANAGED:
                if subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED:
                    LOG.warning("Subcloud %s already managed" % subcloud_id)
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Subcloud is already managed')
                elif not force:
                    if (subcloud.deploy_status != consts.DEPLOY_STATE_DONE and
                            not prestage.is_deploy_status_prestage(
                                subcloud.deploy_status)):
                        LOG.warning("Subcloud %s can be managed only when"
                                    "deploy_status is complete" % subcloud_id)
                        raise exceptions.BadRequest(
                            resource='subcloud',
                            msg='Subcloud can be managed only if deploy status is complete')
                    if subcloud.availability_status != \
                            dccommon_consts.AVAILABILITY_ONLINE:
                        LOG.warning("Subcloud %s is not online" % subcloud_id)
                        raise exceptions.SubcloudNotOnline()
            else:
                LOG.error("Invalid management_state %s" % management_state)
                raise exceptions.InternalError()

        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            management_state=management_state,
            description=description,
            location=location,
            group_id=group_id,
            data_install=data_install
        )

        # Inform orchestrators that subcloud has been updated
        if management_state:
            try:
                # Inform orchestrator of state change
                self.dcorch_rpc_client.update_subcloud_states(
                    context,
                    subcloud.name,
                    management_state,
                    subcloud.availability_status)

                LOG.info('Notifying dcorch, subcloud:%s management: %s, '
                         'availability:%s' % (subcloud.name,
                                              management_state,
                                              subcloud.availability_status))

            except Exception as e:
                LOG.exception(e)
                LOG.warn('Problem informing dcorch of subcloud '
                         'state change, resume to original state, subcloud: %s'
                         % subcloud.name)
                management_state = original_management_state
                subcloud = \
                    db_api.subcloud_update(context, subcloud_id,
                                           management_state=management_state,
                                           description=description,
                                           location=location)

            if management_state == dccommon_consts.MANAGEMENT_UNMANAGED:
                # set all endpoint statuses to unknown, except the dc-cert
                # endpoint which continues to be audited for unmanaged
                # subclouds
                self.state_rpc_client.update_subcloud_endpoint_status_sync(
                    context,
                    subcloud_name=subcloud.name,
                    endpoint_type=None,
                    sync_status=dccommon_consts.SYNC_STATUS_UNKNOWN,
                    ignore_endpoints=[dccommon_consts.ENDPOINT_TYPE_DC_CERT])
            elif management_state == dccommon_consts.MANAGEMENT_MANAGED:
                # Subcloud is managed
                # Tell cert-mon to audit endpoint certificate
                LOG.info('Request certmon audit for %s' % subcloud.name)
                dc_notification = dcmanager_rpc_client.DCManagerNotifications()
                dc_notification.subcloud_managed(context, subcloud.name)

        return db_api.subcloud_db_model_to_dict(subcloud)

    def update_subcloud_with_network_reconfig(self, context, subcloud_id, payload):
        subcloud = db_api.subcloud_get(context, subcloud_id)
        subcloud = db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK
        )
        subcloud_name = payload['name']
        try:
            self._create_intermediate_ca_cert(payload)
            subcloud_inventory_file = self._get_ansible_filename(
                subcloud_name, INVENTORY_FILE_POSTFIX)
            subcloud_params = {'name': subcloud_name,
                               'bootstrap-address': payload.get('bootstrap_address')}
            utils.create_subcloud_inventory(subcloud_params, subcloud_inventory_file)
            overrides_file = self._create_subcloud_update_overrides_file(
                payload, subcloud_name, 'update_values')
            update_command = self.compose_update_command(
                subcloud_name, subcloud_inventory_file)
        except Exception:
            LOG.exception(
                "Failed to prepare subcloud %s for update." % subcloud_name)
            return
        try:
            apply_thread = threading.Thread(
                target=self._run_network_reconfiguration,
                args=(subcloud_name, update_command, overrides_file,
                      payload, context, subcloud))
            apply_thread.start()
        except Exception:
            LOG.exception("Failed to update subcloud %s" % subcloud_name)

    def _run_network_reconfiguration(
        self, subcloud_name, update_command, overrides_file,
        payload, context, subcloud
    ):
        log_file = (os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud_name) +
                    '_playbook_output.log')
        subcloud_id = subcloud.id
        try:
            run_playbook(log_file, update_command)
            utils.delete_subcloud_inventory(overrides_file)
        except PlaybookExecutionFailed:
            msg = utils.find_ansible_error_msg(
                subcloud_name, log_file, consts.DEPLOY_STATE_RECONFIGURING_NETWORK)
            LOG.error(msg)
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
                error_description=msg[0:consts.ERROR_DESCRIPTION_LENGTH]
            )
            return

        self._configure_system_controller_network(context, payload, subcloud)

        db_api.subcloud_update(
            context, subcloud_id, deploy_status=consts.DEPLOY_STATE_DONE
        )

        subcloud = db_api.subcloud_update(
            context,
            subcloud_id,
            description=payload.get('description', subcloud.description),
            management_subnet=payload.get('management_subnet'),
            management_gateway_ip=payload.get('management_gateway_ip'),
            management_start_ip=payload.get('management_start_ip'),
            management_end_ip=payload.get('management_end_ip'),
            location=payload.get('location', subcloud.location),
            group_id=payload.get('group_id', subcloud.group_id),
            data_install=payload.get('data_install', subcloud.data_install)
        )

        # Regenerate the addn_hosts_dc file
        self._create_addn_hosts_dc(context)

    def _configure_system_controller_network(self, context, payload, subcloud):
        subcloud_name = subcloud.name
        subcloud_id = subcloud.id

        try:
            m_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            self._create_subcloud_route(payload, m_ks_client,
                                        subcloud.systemcontroller_gateway_ip)
        except HTTPConflict:
            # The route already exists
            LOG.warning("Failed to create route to subcloud %s" % subcloud_name)
        except Exception:
            LOG.exception(
                "Failed to create route to subcloud %s." % subcloud_name)
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
                error_description=consts.ERROR_DESC_EMPTY
            )
            return
        try:
            self._update_services_endpoint(
                context, payload, subcloud_name, m_ks_client)
        except Exception:
            LOG.exception("Failed to update subcloud %s endpoints" % subcloud_name)
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
                error_description=consts.ERROR_DESC_EMPTY
            )
            return

        # Delete old routes
        if utils.get_management_subnet(payload) != subcloud.management_subnet:
            self._delete_subcloud_routes(m_ks_client, subcloud)

    def _create_subcloud_route(self, payload, keystone_client,
                               systemcontroller_gateway_ip):
        subcloud_subnet = netaddr.IPNetwork(utils.get_management_subnet(payload))
        endpoint = keystone_client.endpoint_cache.get_endpoint('sysinv')
        sysinv_client = SysinvClient(dccommon_consts.DEFAULT_REGION_NAME,
                                     keystone_client.session,
                                     endpoint=endpoint)
        cached_regionone_data = self._get_cached_regionone_data(
            keystone_client, sysinv_client)
        for mgmt_if_uuid in cached_regionone_data['mgmt_interface_uuids']:
            sysinv_client.create_route(mgmt_if_uuid,
                                       str(subcloud_subnet.ip),
                                       subcloud_subnet.prefixlen,
                                       systemcontroller_gateway_ip,
                                       1)

    def _update_services_endpoint(
            self, context, payload, subcloud_name, m_ks_client):
        endpoint_ip = utils.get_management_start_address(payload)
        if netaddr.IPAddress(endpoint_ip).version == 6:
            endpoint_ip = f"[{endpoint_ip}]"

        services_endpoints = {
            "keystone": "https://{}:5001/v3".format(endpoint_ip),
            "sysinv": "https://{}:6386/v1".format(endpoint_ip),
            "fm": "https://{}:18003".format(endpoint_ip),
            "patching": "https://{}:5492".format(endpoint_ip),
            "vim": "https://{}:4546".format(endpoint_ip)
        }

        for endpoint in m_ks_client.keystone_client.endpoints.list(
                region=subcloud_name):
            service_type = m_ks_client.keystone_client.services.get(
                endpoint.service_id).type
            if service_type == dccommon_consts.ENDPOINT_TYPE_PLATFORM:
                admin_endpoint_url = services_endpoints.get('sysinv')
            elif service_type == dccommon_consts.ENDPOINT_TYPE_IDENTITY:
                admin_endpoint_url = services_endpoints.get('keystone')
            elif service_type == dccommon_consts.ENDPOINT_TYPE_PATCHING:
                admin_endpoint_url = services_endpoints.get('patching')
            elif service_type == dccommon_consts.ENDPOINT_TYPE_FM:
                admin_endpoint_url = services_endpoints.get('fm')
            elif service_type == dccommon_consts.ENDPOINT_TYPE_NFV:
                admin_endpoint_url = services_endpoints.get('vim')
            else:
                LOG.exception("Endpoint Type Error: %s" % service_type)
            m_ks_client.keystone_client.endpoints.update(
                endpoint, url=admin_endpoint_url)

        LOG.info("Update services endpoint to %s in subcloud %s" % (
            endpoint_ip, subcloud_name))
        # Update service URLs in subcloud endpoint cache
        self.audit_rpc_client.trigger_subcloud_endpoints_update(
            context, subcloud_name, services_endpoints)
        self.dcorch_rpc_client.update_subcloud_endpoints(
            context, subcloud_name, services_endpoints)
        # Update sysinv URL in cert-mon cache
        dc_notification = dcmanager_rpc_client.DCManagerNotifications()
        dc_notification.subcloud_sysinv_endpoint_update(
            context, subcloud_name, services_endpoints.get("sysinv"))

    def _create_subcloud_update_overrides_file(
            self, payload, subcloud_name, filename_suffix):
        update_overrides_file = os.path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name + '_' +
            filename_suffix + '.yml')

        self._update_override_values(payload)

        with open(update_overrides_file, 'w', encoding='UTF-8') as f_out:
            f_out.write('---\n')
            for key, value in payload['override_values'].items():
                if key in ['ansible_ssh_pass', 'ansible_become_pass']:
                    f_out.write(f"{key}: {value}\n")
                else:
                    f_out.write(f"{key}: {json.dumps(value)}\n")

        return update_overrides_file

    def _update_override_values(self, payload):
        if not payload.get('override_values'):
            payload['override_values'] = {}

        payload['override_values']['ansible_ssh_pass'] = (
            payload['sysadmin_password'])
        payload['override_values']['ansible_become_pass'] = (
            payload['sysadmin_password'])

        payload['override_values']['sc_gateway_address'] = (
            payload['management_gateway_ip'])
        payload['override_values']['sc_floating_address'] = (
            payload['management_start_ip'])
        payload['override_values']['system_controller_network'] = (
            payload['system_controller_network'])
        payload['override_values']['system_controller_network_prefix'] = (
            payload['system_controller_network_prefix'])
        payload['override_values']['sc_subnet'] = payload['management_subnet']

        payload['override_values']['dc_root_ca_cert'] = payload['dc_root_ca_cert']
        payload['override_values']['sc_ca_cert'] = payload['sc_ca_cert']
        payload['override_values']['sc_ca_key'] = payload['sc_ca_key']

    def update_subcloud_sync_endpoint_type(self, context,
                                           subcloud_name,
                                           endpoint_type_list,
                                           openstack_installed):
        operation = 'add' if openstack_installed else 'remove'
        func_switcher = {
            'add': (
                self.dcorch_rpc_client.add_subcloud_sync_endpoint_type,
                db_api.subcloud_status_create
            ),
            'remove': (
                self.dcorch_rpc_client.remove_subcloud_sync_endpoint_type,
                db_api.subcloud_status_delete
            )
        }

        try:
            subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
        except Exception:
            LOG.exception("Failed to get subcloud by name: %s" % subcloud_name)
            raise

        try:
            # Notify dcorch to add/remove sync endpoint type list
            func_switcher[operation][0](self.context, subcloud_name,
                                        endpoint_type_list)
            LOG.info('Notifying dcorch, subcloud: %s new sync endpoint: %s' %
                     (subcloud_name, endpoint_type_list))

            # Update subcloud status table by adding/removing openstack sync
            # endpoint types
            for endpoint_type in endpoint_type_list:
                func_switcher[operation][1](self.context, subcloud.id,
                                            endpoint_type)
            # Update openstack_installed of subcloud table
            db_api.subcloud_update(self.context, subcloud.id,
                                   openstack_installed=openstack_installed)
        except Exception:
            LOG.exception('Problem informing dcorch of subcloud sync endpoint'
                          ' type change, subcloud: %s' % subcloud_name)

    def handle_subcloud_operations_in_progress(self):
        """Identify subclouds in transitory stages and update subcloud

        state to failure.
        """

        LOG.info('Identifying subclouds in transitory stages.')

        subclouds = db_api.subcloud_get_all(self.context)

        for subcloud in subclouds:
            # Identify subclouds in transitory states
            new_deploy_status = TRANSITORY_STATES.get(subcloud.deploy_status)
            new_backup_status = TRANSITORY_BACKUP_STATES.get(subcloud.backup_status)

            # update deploy and backup states to the corresponding failure states
            if new_deploy_status or new_backup_status:
                if new_deploy_status:
                    LOG.info("Changing subcloud %s deploy status from %s to %s."
                             % (subcloud.name, subcloud.deploy_status,
                                new_deploy_status))
                if new_backup_status:
                    LOG.info("Changing subcloud %s backup status from %s to %s."
                             % (subcloud.name, subcloud.backup_status,
                                new_backup_status))

                db_api.subcloud_update(
                    self.context,
                    subcloud.id,
                    deploy_status=new_deploy_status or subcloud.deploy_status,
                    backup_status=new_backup_status or subcloud.backup_status
                )

    @staticmethod
    def prestage_subcloud(context, payload):
        """Subcloud prestaging"""
        return prestage.prestage_subcloud(context, payload)

    @utils.synchronized("regionone-data-cache", external=False)
    def _get_cached_regionone_data(self, regionone_keystone_client, regionone_sysinv_client=None):
        if (not SubcloudManager.regionone_data or
                SubcloudManager.regionone_data['expiry'] <= datetime.datetime.utcnow()):
            user_list = regionone_keystone_client.get_enabled_users(id_only=False)
            for user in user_list:
                if user.name == dccommon_consts.ADMIN_USER_NAME:
                    SubcloudManager.regionone_data['admin_user_id'] = user.id
                elif user.name == dccommon_consts.SYSINV_USER_NAME:
                    SubcloudManager.regionone_data['sysinv_user_id'] = user.id
                elif user.name == dccommon_consts.DCMANAGER_USER_NAME:
                    SubcloudManager.regionone_data['dcmanager_user_id'] = user.id

            project_list = regionone_keystone_client.get_enabled_projects(id_only=False)
            for project in project_list:
                if project.name == dccommon_consts.ADMIN_PROJECT_NAME:
                    SubcloudManager.regionone_data['admin_project_id'] = project.id
                elif project.name == dccommon_consts.SERVICES_USER_NAME:
                    SubcloudManager.regionone_data['services_project_id'] = project.id

            if regionone_sysinv_client is None:
                endpoint = regionone_keystone_client.endpoint_cache.get_endpoint('sysinv')
                regionone_sysinv_client = SysinvClient(
                    dccommon_consts.DEFAULT_REGION_NAME,
                    regionone_keystone_client.session,
                    endpoint=endpoint)

            controllers = regionone_sysinv_client.get_controller_hosts()
            mgmt_interface_uuids = []
            for controller in controllers:
                mgmt_interface = regionone_sysinv_client.get_management_interface(
                    controller.hostname)
                if mgmt_interface is not None:
                    mgmt_interface_uuids.append(mgmt_interface.uuid)
            SubcloudManager.regionone_data['mgmt_interface_uuids'] = mgmt_interface_uuids

            SubcloudManager.regionone_data['mgmt_pool'] = \
                regionone_sysinv_client.get_management_address_pool()
            SubcloudManager.regionone_data['oam_addresses'] = \
                regionone_sysinv_client.get_oam_addresses()

            SubcloudManager.regionone_data['expiry'] = \
                datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            LOG.info("RegionOne cached data updated %s" % SubcloudManager.regionone_data)

        cached_regionone_data = SubcloudManager.regionone_data
        return cached_regionone_data

    def _populate_payload_with_cached_keystone_data(self, cached_data, payload,
                                                    populate_passwords=True):
        payload['system_controller_keystone_admin_user_id'] = \
            cached_data['admin_user_id']
        payload['system_controller_keystone_admin_project_id'] = \
            cached_data['admin_project_id']
        payload['system_controller_keystone_services_project_id'] = \
            cached_data['services_project_id']
        payload['system_controller_keystone_sysinv_user_id'] = \
            cached_data['sysinv_user_id']
        payload['system_controller_keystone_dcmanager_user_id'] = \
            cached_data['dcmanager_user_id']

        if populate_passwords:
            # While at it, add the admin and service user passwords to the
            # payload so they get copied to the overrides file
            payload['ansible_become_pass'] = payload['sysadmin_password']
            payload['ansible_ssh_pass'] = payload['sysadmin_password']
            payload['admin_password'] = str(keyring.get_password('CGCS',
                                                                 'admin'))
