# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2022 Wind River Systems, Inc.
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
import collections
import datetime
import filecmp
import json
import keyring
import netaddr
import os
import threading
import time

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
from dccommon.utils import run_playbook

from dcorch.rpc import client as dcorch_rpc_client

from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common.consts import INVENTORY_FILE_POSTFIX
from dcmanager.common import context as dcmanager_context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as dcmanager_rpc_client

from fm_api import constants as fm_const
from fm_api import fm_api

LOG = logging.getLogger(__name__)

# Name of our distributed cloud addn_hosts file for dnsmasq
# to read.  This file is referenced in dnsmasq.conf
ADDN_HOSTS_DC = 'dnsmasq.addn_hosts_dc'

# Subcloud configuration paths
ANSIBLE_SUBCLOUD_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/bootstrap.yml'
ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/install.yml'
ANSIBLE_SUBCLOUD_RESTORE_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/restore_platform.yml'
ANSIBLE_HOST_VALIDATION_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/validate_host.yml'
ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/rehome_subcloud.yml'

USERS_TO_REPLICATE = [
    'sysinv',
    'patching',
    'vim',
    'mtce',
    'fm',
    'barbican',
    'dcmanager']

# The timeout of the rehome playbook is set to 180 seconds as it takes a
# long time for privilege escalation before resetting the host route and
# LDAP server address in a subcloud.
REHOME_PLAYBOOK_TIMEOUT = "180"  # 180 seconds
SC_INTERMEDIATE_CERT_DURATION = "8760h"  # 1 year = 24 hours x 365
SC_INTERMEDIATE_CERT_RENEW_BEFORE = "720h"  # 30 days
CERT_NAMESPACE = "dc-cert"

TRANSITORY_STATES = {consts.DEPLOY_STATE_NONE: consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                     consts.DEPLOY_STATE_PRE_DEPLOY: consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                     consts.DEPLOY_STATE_PRE_INSTALL: consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                     consts.DEPLOY_STATE_INSTALLING: consts.DEPLOY_STATE_INSTALL_FAILED,
                     consts.DEPLOY_STATE_BOOTSTRAPPING: consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                     consts.DEPLOY_STATE_DEPLOYING: consts.DEPLOY_STATE_DEPLOY_FAILED,
                     consts.DEPLOY_STATE_MIGRATING_DATA: consts.DEPLOY_STATE_DATA_MIGRATION_FAILED,
                     consts.DEPLOY_STATE_PRE_RESTORE: consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
                     consts.DEPLOY_STATE_RESTORING: consts.DEPLOY_STATE_RESTORE_FAILED,
                     consts.PRESTAGE_STATE_PREPARE: consts.PRESTAGE_STATE_FAILED,
                     consts.PRESTAGE_STATE_PACKAGES: consts.PRESTAGE_STATE_FAILED,
                     consts.PRESTAGE_STATE_IMAGES: consts.PRESTAGE_STATE_FAILED,
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
            consts.ANSIBLE_OVERRIDES_PATH,
            subcloud_name + postfix)
        return ansible_filename

    def compose_install_command(self, subcloud_name, ansible_subcloud_inventory_file):
        install_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
                  subcloud_name + '/' + "install_values.yml"]
        return install_command

    def compose_apply_command(self, subcloud_name, ansible_subcloud_inventory_file):
        apply_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_PLAYBOOK, "-i",
            ansible_subcloud_inventory_file,
            "--limit", subcloud_name
        ]
        # Add the overrides dir and region_name so the playbook knows
        # which overrides to load
        apply_command += [
            "-e", str("override_files_dir='%s' region_name=%s") % (
                consts.ANSIBLE_OVERRIDES_PATH, subcloud_name)]
        return apply_command

    def compose_deploy_command(self, subcloud_name, ansible_subcloud_inventory_file, payload):
        deploy_command = [
            "ansible-playbook", payload[consts.DEPLOY_PLAYBOOK],
            "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
                  subcloud_name + '_deploy_values.yml',
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name
            ]
        return deploy_command

    def compose_check_target_command(self, subcloud_name,
                                     ansible_subcloud_inventory_file, payload):
        check_target_command = [
            "ansible-playbook", ANSIBLE_HOST_VALIDATION_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
            subcloud_name + "_check_target_values.yml"]

        return check_target_command

    def compose_restore_command(self, subcloud_name,
                                ansible_subcloud_inventory_file, payload):
        restore_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_RESTORE_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
            subcloud_name + "_restore_values.yml"]

        return restore_command

    def compose_rehome_command(self, subcloud_name, ansible_subcloud_inventory_file):
        rehome_command = [
            "ansible-playbook", ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK,
            "-i", ansible_subcloud_inventory_file,
            "--limit", subcloud_name,
            "--timeout", REHOME_PLAYBOOK_TIMEOUT,
            "-e", str("override_files_dir='%s' region_name=%s") % (
                consts.ANSIBLE_OVERRIDES_PATH, subcloud_name)]
        return rehome_command

    def add_subcloud(self, context, payload):
        """Add subcloud and notify orchestrators.

        :param context: request context object
        :param payload: subcloud configuration
        """
        LOG.info("Adding subcloud %s." % payload['name'])
        subcloud_id = db_api.subcloud_get_by_name(context, payload['name']).id

        # Check the migrate option from payload
        migrate_str = payload.get('migrate', '')
        migrate_flag = (migrate_str.lower() == 'true')
        if migrate_flag:
            subcloud = db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_REHOME)
        else:
            subcloud = db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_DEPLOY)

        try:
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            # Create a new route to this subcloud on the management interface
            # on both controllers.
            m_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            subcloud_subnet = netaddr.IPNetwork(payload['management_subnet'])
            endpoint = m_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(dccommon_consts.DEFAULT_REGION_NAME,
                                         m_ks_client.session,
                                         endpoint=endpoint)
            LOG.debug("Getting cached regionone data for %s" % subcloud.name)
            cached_regionone_data = self._get_cached_regionone_data(m_ks_client, sysinv_client)
            for mgmt_if_uuid in cached_regionone_data['mgmt_interface_uuids']:
                sysinv_client.create_route(mgmt_if_uuid,
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
            endpoint_ip = payload['management_start_address']
            if netaddr.IPAddress(endpoint_ip).version == 6:
                endpoint_ip = '[' + endpoint_ip + ']'

            for service in m_ks_client.services_list:
                if service.type == dccommon_consts.ENDPOINT_TYPE_PLATFORM:
                    admin_endpoint_url = "https://{}:6386/v1".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dccommon_consts.ENDPOINT_TYPE_IDENTITY:
                    admin_endpoint_url = "https://{}:5001/v3".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dccommon_consts.ENDPOINT_TYPE_PATCHING:
                    admin_endpoint_url = "https://{}:5492".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dccommon_consts.ENDPOINT_TYPE_FM:
                    admin_endpoint_url = "https://{}:18003".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dccommon_consts.ENDPOINT_TYPE_NFV:
                    admin_endpoint_url = "https://{}:4546".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})

            if len(endpoint_config) < 5:
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
                cached_regionone_data, payload)

            if "install_values" in payload:
                payload['install_values']['ansible_ssh_pass'] = \
                    payload['sysadmin_password']
                if 'image' not in payload['install_values']:
                    matching_iso, matching_sig = utils.get_vault_load_files(
                        SW_VERSION)
                    payload['install_values'].update({'image': matching_iso})

            deploy_command = None
            if "deploy_playbook" in payload:
                self._prepare_for_deployment(payload, subcloud.name)
                deploy_command = self.compose_deploy_command(
                    subcloud.name,
                    ansible_subcloud_inventory_file,
                    payload)

            del payload['sysadmin_password']
            payload['users'] = dict()
            for user in USERS_TO_REPLICATE:
                payload['users'][user] = \
                    str(keyring.get_password(
                        user, dccommon_consts.SERVICES_USER_NAME))
            # The password of smapi user is expected to the aligned during rehoming
            # a subcloud. Add smapi into the user to replace list.
            if migrate_flag:
                payload['users']['smapi'] = \
                    str(keyring.get_password(
                        'smapi', dccommon_consts.SERVICES_USER_NAME))

            # Create the ansible inventory for the new subcloud
            utils.create_subcloud_inventory(payload,
                                            ansible_subcloud_inventory_file)

            # create subcloud intermediate certificate and pass in keys
            self._create_intermediate_ca_cert(payload)

            # Write this subclouds overrides to file
            # NOTE: This file should not be deleted if subcloud add fails
            # as it is used for debugging
            self._write_subcloud_ansible_config(cached_regionone_data, payload)

            if migrate_flag:
                rehome_command = self.compose_rehome_command(
                    subcloud.name,
                    ansible_subcloud_inventory_file)
                apply_thread = threading.Thread(
                    target=self.run_deploy,
                    args=(subcloud, payload, context,
                          None, None, None, None, None, rehome_command))
            else:
                install_command = None
                if "install_values" in payload:
                    install_command = self.compose_install_command(
                        subcloud.name,
                        ansible_subcloud_inventory_file)
                apply_command = self.compose_apply_command(
                    subcloud.name,
                    ansible_subcloud_inventory_file)
                apply_thread = threading.Thread(
                    target=self.run_deploy,
                    args=(subcloud, payload, context,
                          install_command, apply_command, deploy_command))

            apply_thread.start()

            return db_api.subcloud_db_model_to_dict(subcloud)

        except Exception:
            LOG.exception("Failed to create subcloud %s" % payload['name'])
            # If we failed to create the subcloud, update the
            # deployment status
            if migrate_flag:
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_REHOME_PREP_FAILED)
            else:
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_DEPLOY_PREP_FAILED)

    def reconfigure_subcloud(self, context, subcloud_id, payload):
        """Reconfigure subcloud

        :param context: request context object
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

            deploy_command = None
            if "deploy_playbook" in payload:
                self._prepare_for_deployment(payload, subcloud.name)
                deploy_command = self.compose_deploy_command(
                    subcloud.name,
                    ansible_subcloud_inventory_file,
                    payload)

            del payload['sysadmin_password']
            apply_thread = threading.Thread(
                target=self.run_deploy,
                args=(subcloud, payload, context, None, None, deploy_command))
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

            deploy_command = None
            if "deploy_playbook" in payload:
                self._prepare_for_deployment(payload, subcloud.name)
                deploy_command = self.compose_deploy_command(
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
                ansible_subcloud_inventory_file)
            apply_command = self.compose_apply_command(
                subcloud.name,
                ansible_subcloud_inventory_file)
            apply_thread = threading.Thread(
                target=self.run_deploy,
                args=(subcloud, payload, context,
                      install_command, apply_command, deploy_command))
            apply_thread.start()
            return db_api.subcloud_db_model_to_dict(subcloud)
        except Exception:
            LOG.exception("Failed to reinstall subcloud %s" % subcloud.name)
            # If we failed to reinstall the subcloud, update the
            # deployment status
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)

    def _create_check_target_override_file(self, payload, subcloud_name):
        check_target_override_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH, subcloud_name +
            '_check_target_values.yml')

        with open(check_target_override_file, 'w') as f_out:
            f_out.write(
                '---\n'
            )
            for k, v in payload['check_target_values'].items():
                f_out.write("%s: %s\n" % (k, json.dumps(v)))

    def _create_restore_override_file(self, payload, subcloud_name):
        restore_override_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH, subcloud_name +
            '_restore_values.yml')

        with open(restore_override_file, 'w') as f_out:
            f_out.write(
                '---\n'
            )
            for k, v in payload['restore_values'].items():
                f_out.write("%s: %s\n" % (k, json.dumps(v)))

    def _prepare_for_restore(self, payload, subcloud_name):
        payload['check_target_values'] = dict()
        payload['check_target_values']['ansible_ssh_pass'] = \
            payload['sysadmin_password']
        payload['check_target_values']['software_version'] = SW_VERSION
        payload['check_target_values']['bootstrap_address'] = \
            payload['bootstrap-address']
        payload['check_target_values']['check_bootstrap_address'] = 'true'
        payload['check_target_values']['check_patches'] = 'false'

        self._create_check_target_override_file(payload, subcloud_name)

        payload['restore_values']['ansible_ssh_pass'] = \
            payload['sysadmin_password']
        payload['restore_values']['ansible_become_pass'] = \
            payload['sysadmin_password']
        payload['restore_values']['admin_password'] = \
            str(keyring.get_password('CGCS', 'admin'))
        payload['restore_values']['skip_patches_restore'] = 'true'

        self._create_restore_override_file(payload, subcloud_name)

    def restore_subcloud(self, context, subcloud_id, payload):
        """Restore subcloud

        :param context: request context object
        :param subcloud_id: subcloud id from db
        :param payload: subcloud restore detail
        """

        # Retrieve the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)

        if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
            raise exceptions.SubcloudNotUnmanaged()

        db_api.subcloud_update(context, subcloud_id,
                               deploy_status=consts.DEPLOY_STATE_PRE_RESTORE)

        try:
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = self._get_ansible_filename(
                subcloud.name, INVENTORY_FILE_POSTFIX)

            # Add parameters used to generate inventory
            payload['name'] = subcloud.name
            payload['bootstrap-address'] = \
                payload['install_values']['bootstrap_address']
            payload['software_version'] = SW_VERSION

            install_command = None

            if payload['with_install']:
                # Redfish capable subclouds
                LOG.info("Reinstalling subcloud %s." % subcloud.name)

                # Disegard the current 'image' config. Always reinstall with
                # the system controller active image in dc-vault.
                matching_iso, matching_sig = utils.get_vault_load_files(SW_VERSION)

                payload['install_values'].update({'image': matching_iso})
                payload['install_values']['ansible_ssh_pass'] = \
                    payload['sysadmin_password']

                utils.create_subcloud_inventory(payload,
                                                ansible_subcloud_inventory_file)

                install_command = self.compose_install_command(
                    subcloud.name, ansible_subcloud_inventory_file)

            else:
                # Non Redfish capable subcloud
                # Shouldn't get here as the API has already rejected the request.
                return

            # Prepare for restore
            self._prepare_for_restore(payload, subcloud.name)
            check_target_command = self.compose_check_target_command(
                subcloud.name, ansible_subcloud_inventory_file, payload)

            restore_command = self.compose_restore_command(
                subcloud.name, ansible_subcloud_inventory_file, payload)

            apply_thread = threading.Thread(
                target=self.run_deploy,
                args=(subcloud, payload, context,
                      install_command, None, None, check_target_command, restore_command))
            apply_thread.start()
            return db_api.subcloud_db_model_to_dict(subcloud)

        except Exception:
            LOG.exception("Failed to restore subcloud %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud_id,
                deploy_status=consts.DEPLOY_STATE_RESTORE_PREP_FAILED)

    # TODO(kmacleod) add outer try/except here to catch and log unexpected
    # exception. As this stands, any uncaught exception is a silent (unlogged)
    # failure
    @staticmethod
    def run_deploy(subcloud, payload, context,
                   install_command=None, apply_command=None,
                   deploy_command=None, check_target_command=None,
                   restore_command=None, rehome_command=None):

        log_file = os.path.join(consts.DC_ANSIBLE_LOG_DIR, subcloud.name) + \
            '_playbook_output.log'
        if install_command:
            LOG.info("Preparing remote install of %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)
            try:
                install = SubcloudInstall(context, subcloud.name)
                install.prep(consts.ANSIBLE_OVERRIDES_PATH,
                             payload['install_values'])
            except Exception as e:
                LOG.exception(e)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)
                LOG.error(str(e))
                install.cleanup()
                return

            # Run the remote install playbook
            LOG.info("Starting remote install of %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_INSTALLING)
            try:
                install.install(consts.DC_ANSIBLE_LOG_DIR, install_command)
            except Exception as e:
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)
                LOG.error(str(e))
                install.cleanup()
                return
            install.cleanup()
            LOG.info("Successfully installed %s" % subcloud.name)

        # Leave the following block here in case there is another use
        # case besides subcloud restore where validating host post
        # fresh install is necessary.
        if check_target_command:
            try:
                run_playbook(log_file, check_target_command)
            except PlaybookExecutionFailed:
                msg = "Failed to run the validate host playbook" \
                      " for subcloud %s, check individual log at " \
                      "%s for detailed output." % (
                          subcloud.name,
                          log_file)
                LOG.error(msg)
                if restore_command:
                    db_api.subcloud_update(
                        context, subcloud.id,
                        deploy_status=consts.DEPLOY_STATE_RESTORE_PREP_FAILED)
                return

            LOG.info("Successfully checked subcloud %s" % subcloud.name)

        if apply_command:
            try:
                # Update the subcloud to bootstrapping
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)
            except Exception as e:
                LOG.exception(e)
                raise e

            # Run the ansible boostrap-subcloud playbook
            LOG.info("Starting bootstrap of %s" % subcloud.name)
            try:
                run_playbook(log_file, apply_command)
            except PlaybookExecutionFailed:
                msg = "Failed to run the subcloud bootstrap playbook" \
                      " for subcloud %s, check individual log at " \
                      "%s for detailed output." % (
                          subcloud.name,
                          log_file)
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)
                return
            LOG.info("Successfully bootstrapped %s" % subcloud.name)

        if deploy_command:
            # Run the custom deploy playbook
            LOG.info("Starting deploy of %s" % subcloud.name)
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_DEPLOYING)

            try:
                run_playbook(log_file, deploy_command)
            except PlaybookExecutionFailed:
                msg = "Failed to run the subcloud deploy playbook" \
                      " for subcloud %s, check individual log at " \
                      "%s for detailed output." % (
                          subcloud.name,
                          log_file)
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_DEPLOY_FAILED)
                return
            LOG.info("Successfully deployed %s" % subcloud.name)
        elif restore_command:
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_RESTORING)

            # Run the restore platform playbook
            try:
                run_playbook(log_file, restore_command)
            except PlaybookExecutionFailed:
                msg = "Failed to run the subcloud restore playbook" \
                      " for subcloud %s, check individual log at " \
                      "%s for detailed output." % (
                          subcloud.name,
                          log_file)
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_RESTORE_FAILED)
                return
            LOG.info("Successfully restored controller-0 of subcloud %s" %
                     subcloud.name)

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

        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE)

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

        overrides_file = os.path.join(consts.ANSIBLE_OVERRIDES_PATH,
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
            consts.ANSIBLE_OVERRIDES_PATH, subcloud_name +
            '_deploy_values.yml')

        with open(deploy_values_file, 'w') as f_out_deploy_values_file:
            json.dump(payload['deploy_values'], f_out_deploy_values_file)

    def _prepare_for_deployment(self, payload, subcloud_name):
        payload['deploy_values'] = dict()
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

    def _delete_subcloud_routes(self, context, subcloud):
        """Delete the routes to this subcloud"""

        keystone_client = OpenStackDriver(
            region_name=dccommon_consts.DEFAULT_REGION_NAME,
            region_clients=None).keystone_client

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
            if "SubcloudNotFound" in e:
                pass

        # delete the associated alarm entry
        try:
            db_api.subcloud_alarms_delete(context, subcloud.name)
        except RemoteError as e:
            if "SubcloudNotFound" in e:
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
        self._delete_subcloud_routes(context, subcloud)

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

        # Regenerate the addn_hosts_dc file
        self._create_addn_hosts_dc(context)

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
        for alarm_id, entity_instance_id in (
                (fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                 "subcloud=%s" % subcloud.name),
                (fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                 "subcloud=%s.resource=%s" %
                 (subcloud.name, dccommon_consts.ENDPOINT_TYPE_DC_CERT))):
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

        subcloud = db_api.subcloud_update(context,
                                          subcloud_id,
                                          management_state=management_state,
                                          description=description,
                                          location=location,
                                          group_id=group_id,
                                          data_install=data_install)

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
                LOG.info('Request for managed audit for %s' % subcloud.name)
                dc_notification = dcmanager_rpc_client.DCManagerNotifications()
                dc_notification.subcloud_managed(context, subcloud.name)
                # Since sysinv user is sync'ed during bootstrap, trigger the
                # related audits. Patch and load audits are delayed until the
                # identity resource synchronized by dcdbsync is complete.
                exclude_endpoints = [dccommon_consts.ENDPOINT_TYPE_PATCHING,
                                     dccommon_consts.ENDPOINT_TYPE_LOAD]
                self.audit_rpc_client.trigger_subcloud_audits(
                    context, subcloud_id, exclude_endpoints)

        return db_api.subcloud_db_model_to_dict(subcloud)

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
        """Identify subclouds in transitory stages and update subcloud deploy state to failure."""

        LOG.info('Identifying subclouds in transitory stages.')

        # identify subclouds in transitory states
        subclouds_in_transitory_states = [subcloud for subcloud in
                                          db_api.subcloud_get_all(self.context)
                                          if subcloud.deploy_status in TRANSITORY_STATES.keys()]

        # update the deploy_state to the corresponding failure state
        for subcloud in subclouds_in_transitory_states:
            new_deploy_status = TRANSITORY_STATES[subcloud.deploy_status]
            LOG.info("Changing subcloud %s deploy status from %s to %s."
                     % (subcloud.name, subcloud.deploy_status, new_deploy_status))
            db_api.subcloud_update(
                self.context,
                subcloud.id,
                deploy_status=new_deploy_status)

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

    def _populate_payload_with_cached_keystone_data(self, cached_data, payload):
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

        # While at it, add the admin and service user passwords to the payload so
        # they get copied to the overrides file
        payload['ansible_become_pass'] = payload['sysadmin_password']
        payload['ansible_ssh_pass'] = payload['sysadmin_password']
        payload['admin_password'] = str(keyring.get_password('CGCS',
                                                             'admin'))
