# Copyright 2017 Ericsson AB.
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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import datetime
from eventlet.green import subprocess
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

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import kubeoperator

from dcorch.common import consts as dcorch_consts
from dcorch.rpc import client as dcorch_rpc_client

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import utils

from dcmanager.db import api as db_api
from dcmanager.manager.subcloud_install import SubcloudInstall

from fm_api import constants as fm_const
from fm_api import fm_api

LOG = logging.getLogger(__name__)

# Name of our distributed cloud addn_hosts file for dnsmasq
# to read.  This file is referenced in dnsmasq.conf
ADDN_HOSTS_DC = 'dnsmasq.addn_hosts_dc'

# Subcloud configuration paths
INVENTORY_FILE_POSTFIX = '_inventory.yml'
ANSIBLE_SUBCLOUD_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/bootstrap.yml'
ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/install.yml'
DC_LOG_DIR = '/var/log/dcmanager/'

USERS_TO_REPLICATE = [
    'sysinv',
    'patching',
    'vim',
    'mtce',
    'fm',
    'barbican']

SERVICES_USER = 'services'

SC_INTERMEDIATE_CERT_DURATION = "87600h"
SC_INTERMEDIATE_CERT_RENEW_BEFORE = "720h"
CERT_NAMESPACE = "dc-cert"


def sync_update_subcloud_endpoint_status(func):
    """Synchronized lock decorator for _update_subcloud_endpoint_status. """

    def _get_lock_and_call(*args, **kwargs):
        """Get a single fair lock per subcloud based on subcloud name. """

        # subcloud name is the 3rd argument to
        # _update_subcloud_endpoint_status()
        @utils.synchronized(args[2], external=False, fair=True)
        def _call_func(*args, **kwargs):
            return func(*args, **kwargs)

        return _call_func(*args, **kwargs)

    return _get_lock_and_call


class SubcloudManager(manager.Manager):
    """Manages tasks related to subclouds."""

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SubcloudManager initialization...'))

        super(SubcloudManager, self).__init__(service_name="subcloud_manager",
                                              *args, **kwargs)
        self.context = context.get_admin_context()
        self.dcorch_rpc_client = dcorch_rpc_client.EngineClient()
        self.fm_api = fm_api.FaultAPIs()

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
            "apiVersion": "cert-manager.io/v1alpha2",
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
            if 'ca.crt' not in data or \
                    'tls.crt' not in data or 'tls.key' not in data:
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

    def add_subcloud(self, context, payload):
        """Add subcloud and notify orchestrators.

        :param context: request context object
        :param name: name of subcloud to add
        :param payload: subcloud configuration
        """
        LOG.info("Adding subcloud %s." % payload['name'])
        subcloud = db_api.subcloud_get_by_name(context, payload['name'])

        db_api.subcloud_update(
            context, subcloud.id,
            deploy_status=consts.DEPLOY_STATE_PRE_DEPLOY)

        # Populate the subcloud status table with all endpoints
        for endpoint in dcorch_consts.ENDPOINT_TYPES_LIST:
            db_api.subcloud_status_create(context,
                                          subcloud.id,
                                          endpoint)

        try:
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = os.path.join(
                consts.ANSIBLE_OVERRIDES_PATH,
                subcloud.name + INVENTORY_FILE_POSTFIX)

            # Create a new route to this subcloud on the management interface
            # on both controllers.
            m_ks_client = KeystoneClient()
            subcloud_subnet = netaddr.IPNetwork(payload['management_subnet'])
            session = m_ks_client.endpoint_cache.get_session_from_token(
                context.auth_token, context.project)
            sysinv_client = SysinvClient(consts.DEFAULT_REGION_NAME, session)
            controllers = sysinv_client.get_controller_hosts()
            for controller in controllers:
                management_interface = sysinv_client.get_management_interface(
                    controller.hostname)
                if management_interface is not None:
                    sysinv_client.create_route(
                        management_interface.uuid,
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
                if service.type == dcorch_consts.ENDPOINT_TYPE_PLATFORM:
                    admin_endpoint_url = "https://{}:6386/v1".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dcorch_consts.ENDPOINT_TYPE_IDENTITY:
                    admin_endpoint_url = "https://{}:5001/v3".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dcorch_consts.ENDPOINT_TYPE_PATCHING:
                    admin_endpoint_url = "https://{}:5492".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dcorch_consts.ENDPOINT_TYPE_FM:
                    admin_endpoint_url = "https://{}:18003".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})
                elif service.type == dcorch_consts.ENDPOINT_TYPE_NFV:
                    admin_endpoint_url = "https://{}:4546".format(endpoint_ip)
                    endpoint_config.append({"id": service.id,
                                            "admin_endpoint_url": admin_endpoint_url})

            if len(endpoint_config) < 5:
                raise exceptions.BadRequest(
                    resource='subcloud',
                    msg='Missing service in SystemController')

            for endpoint in endpoint_config:
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

            # Query system controller keystone admin user/project IDs,
            # services project id and sysinv user id and store in payload so
            # they get copied to the override file
            admin_user = m_ks_client.get_user_by_name(
                dccommon_consts.ADMIN_USER_NAME)
            admin_project = m_ks_client.get_project_by_name(
                dccommon_consts.ADMIN_PROJECT_NAME)
            services_project = m_ks_client.get_project_by_name(SERVICES_USER)
            sysinv_user = m_ks_client.get_user_by_name(
                dccommon_consts.SYSINV_USER_NAME)
            payload['system_controller_keystone_admin_user_id'] = \
                admin_user.id
            payload['system_controller_keystone_admin_project_id'] = \
                admin_project.id
            payload['system_controller_keystone_services_project_id'] = \
                services_project.id
            payload['system_controller_keystone_sysinv_user_id'] = \
                sysinv_user.id

            # Add the admin and service user passwords to the payload so they
            # get copied to the override file
            payload['ansible_become_pass'] = payload['sysadmin_password']
            payload['ansible_ssh_pass'] = payload['sysadmin_password']
            payload['admin_password'] = str(keyring.get_password('CGCS',
                                                                 'admin'))

            if "install_values" in payload:
                payload['install_values']['ansible_ssh_pass'] = \
                    payload['sysadmin_password']

            if "deploy_playbook" in payload:
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

            del payload['sysadmin_password']

            payload['users'] = dict()
            for user in USERS_TO_REPLICATE:
                payload['users'][user] = \
                    str(keyring.get_password(user, SERVICES_USER))

            # Create the ansible inventory for the new subcloud
            self._create_subcloud_inventory(payload,
                                            ansible_subcloud_inventory_file)

            # create subcloud intermediate certificate and pass in keys
            self._create_intermediate_ca_cert(payload)

            # Write this subclouds overrides to file
            # NOTE: This file should not be deleted if subcloud add fails
            # as it is used for debugging
            self._write_subcloud_ansible_config(context, payload)

            if "deploy_playbook" in payload:
                self._write_deploy_files(payload)

            install_command = None
            if "install_values" in payload:
                install_command = [
                    "ansible-playbook", ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
                    "-i", ansible_subcloud_inventory_file,
                    "--limit", subcloud.name,
                    "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
                          payload['name'] + '/' + "install_values.yml"
                ]

            apply_command = [
                "ansible-playbook", ANSIBLE_SUBCLOUD_PLAYBOOK, "-i",
                ansible_subcloud_inventory_file,
                "--limit", subcloud.name
            ]

            # Add the overrides dir and region_name so the playbook knows
            # which overrides to load
            apply_command += [
                "-e", str("override_files_dir='%s' region_name=%s") % (
                    consts.ANSIBLE_OVERRIDES_PATH, subcloud.name)]

            deploy_command = None
            if "deploy_playbook" in payload:
                deploy_command = [
                    "ansible-playbook", payload[consts.DEPLOY_PLAYBOOK],
                    "-e", "@%s" % consts.ANSIBLE_OVERRIDES_PATH + "/" +
                          payload['name'] + "_deploy_values.yml",
                    "-i", ansible_subcloud_inventory_file,
                    "--limit", subcloud.name
                ]

            apply_thread = threading.Thread(
                target=self.run_deploy,
                args=(install_command, apply_command, deploy_command, subcloud,
                      payload, context))
            apply_thread.start()

            return db_api.subcloud_db_model_to_dict(subcloud)

        except Exception:
            LOG.exception("Failed to create subcloud %s" % payload['name'])
            # If we failed to create the subcloud, update the
            # deployment status
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_DEPLOY_PREP_FAILED)

    @staticmethod
    def run_deploy(install_command, apply_command, deploy_command, subcloud,
                   payload, context):

        if install_command:
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
                LOG.error(e.message)
                install.cleanup()
                return

            # Run the remote install playbook
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_INSTALLING)
            try:
                install.install(DC_LOG_DIR, install_command)
            except Exception as e:
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)
                LOG.error(e.message)
                install.cleanup()
                return
            install.cleanup()
            LOG.info("Successfully installed subcloud %s" % subcloud.name)

        # Update the subcloud to bootstrapping
        try:
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Run the ansible boostrap-subcloud playbook
        log_file = \
            DC_LOG_DIR + subcloud.name + '_bootstrap_' + \
            str(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')) \
            + '.log'
        with open(log_file, "w") as f_out_log:
            try:
                subprocess.check_call(apply_command,
                                      stdout=f_out_log,
                                      stderr=f_out_log)
            except subprocess.CalledProcessError as ex:
                msg = "Failed to run the subcloud bootstrap playbook" \
                      " for subcloud %s, check individual log at " \
                      "%s for detailed output." % (
                          subcloud.name,
                          log_file)
                ex.cmd = 'ansible-playbook'
                LOG.error(msg)
                db_api.subcloud_update(
                    context, subcloud.id,
                    deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)
                return
            LOG.info("Successfully bootstrapped subcloud %s" %
                     subcloud.name)

        if deploy_command:
            # Run the custom deploy playbook
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_DEPLOYING)
            log_file = \
                DC_LOG_DIR + subcloud.name + '_deploy_' + \
                str(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')) \
                + '.log'
            with open(log_file, "w") as f_out_log:
                try:
                    subprocess.check_call(deploy_command,
                                          stdout=f_out_log,
                                          stderr=f_out_log)
                except subprocess.CalledProcessError as ex:
                    msg = "Failed to run the subcloud deploy playbook" \
                          " for subcloud %s, check individual log at " \
                          "%s for detailed output." % (
                              subcloud.name,
                              log_file)
                    ex.cmd = 'deploy-playbook'
                    LOG.error(msg)
                    db_api.subcloud_update(
                        context, subcloud.id,
                        deploy_status=consts.DEPLOY_STATE_DEPLOY_FAILED)
                    return
                LOG.info("Successfully deployed subcloud %s" %
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

    def _create_subcloud_inventory(self,
                                   subcloud,
                                   inventory_file):
        """Create the inventory file for the specified subcloud"""

        # Delete the file if it already exists
        if os.path.isfile(inventory_file):
            os.remove(inventory_file)

        with open(inventory_file, 'w') as f_out_inventory:
            f_out_inventory.write(
                '---\n'
                'all:\n'
                '  vars:\n'
                '    ansible_ssh_user: sysadmin\n'
                '  hosts:\n'
                '    ' + subcloud['name'] + ':\n'
                '      ansible_host: ' +
                subcloud['bootstrap-address'] + '\n'
            )

    def _delete_subcloud_inventory(self,
                                   inventory_file):
        """Delete the inventory file for the specified subcloud"""

        # Delete the file if it exists
        if os.path.isfile(inventory_file):
            os.remove(inventory_file)

    def _write_subcloud_ansible_config(self, context, payload):
        """Create the override file for usage with the specified subcloud"""

        overrides_file = os.path.join(consts.ANSIBLE_OVERRIDES_PATH,
                                      payload['name'] + '.yml')

        m_ks_client = KeystoneClient()
        session = m_ks_client.endpoint_cache.get_session_from_token(
            context.auth_token, context.project)
        sysinv_client = SysinvClient(consts.DEFAULT_REGION_NAME, session)

        mgmt_pool = sysinv_client.get_management_address_pool()
        mgmt_floating_ip = mgmt_pool.floating_address
        mgmt_subnet = "%s/%d" % (mgmt_pool.network, mgmt_pool.prefix)

        oam_addresses = sysinv_client.get_oam_addresses()
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

    def _write_deploy_files(self, payload):
        """Create the deploy value files for the subcloud"""

        deploy_values_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH, payload['name'] +
            '_deploy_values.yml')

        with open(deploy_values_file, 'w') as f_out_deploy_values_file:
            json.dump(payload['deploy_values'], f_out_deploy_values_file)

    def _delete_subcloud_routes(self, context, subcloud):
        """Delete the routes to this subcloud"""

        keystone_client = KeystoneClient()
        session = keystone_client.endpoint_cache.get_session_from_token(
            context.auth_token, context.project)

        # Delete the route to this subcloud on the management interface on
        # both controllers.
        management_subnet = netaddr.IPNetwork(subcloud.management_subnet)
        sysinv_client = SysinvClient(consts.DEFAULT_REGION_NAME, session)
        controllers = sysinv_client.get_controller_hosts()
        for controller in controllers:
            management_interface = sysinv_client.get_management_interface(
                controller.hostname)
            if management_interface is not None:
                sysinv_client.delete_route(
                    management_interface.uuid,
                    str(management_subnet.ip),
                    management_subnet.prefixlen,
                    str(netaddr.IPAddress(
                        subcloud.systemcontroller_gateway_ip)),
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
        keystone_client = KeystoneClient()

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
        self._delete_subcloud_inventory(ansible_subcloud_inventory_file)

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
        if subcloud.management_state != consts.MANAGEMENT_UNMANAGED:
            raise exceptions.SubcloudNotUnmanaged()

        if subcloud.availability_status == \
                consts.AVAILABILITY_ONLINE:
            raise exceptions.SubcloudNotOffline()

        # Ansible inventory filename for the specified subcloud
        ansible_subcloud_inventory_file = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH,
            subcloud.name + INVENTORY_FILE_POSTFIX)

        self._remove_subcloud_details(context,
                                      subcloud,
                                      ansible_subcloud_inventory_file)

        # Clear the offline fault associated with this subcloud as we
        # are deleting it. Note that endpoint out-of-sync alarms should
        # have been cleared when the subcloud was unmanaged and the endpoint
        # sync statuses were set to unknown.
        entity_instance_id = "subcloud=%s" % subcloud.name

        try:
            subcloud_offline = fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE
            fault = self.fm_api.get_fault(subcloud_offline,
                                          entity_instance_id)

            if fault:
                self.fm_api.clear_fault(subcloud_offline,
                                        entity_instance_id)
        except Exception as e:
            LOG.info("Problem clearing offline fault for "
                     "subcloud %s" % subcloud.name)
            LOG.exception(e)

    def update_subcloud(self,
                        context,
                        subcloud_id,
                        management_state=None,
                        description=None,
                        location=None,
                        group_id=None):
        """Update subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param management_state: new management state
        :param description: new description
        :param location: new location
        :param group_id: new subcloud group id
        """

        LOG.info("Updating subcloud %s." % subcloud_id)

        # Get the subcloud details from the database
        subcloud = db_api.subcloud_get(context, subcloud_id)
        original_management_state = subcloud.management_state

        # Semantic checking
        if management_state:
            if management_state == consts.MANAGEMENT_UNMANAGED:
                if subcloud.management_state == consts.MANAGEMENT_UNMANAGED:
                    LOG.warning("Subcloud %s already unmanaged" % subcloud_id)
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Subcloud is already unmanaged')
            elif management_state == consts.MANAGEMENT_MANAGED:
                if subcloud.management_state == consts.MANAGEMENT_MANAGED:
                    LOG.warning("Subcloud %s already managed" % subcloud_id)
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Subcloud is already managed')
                if subcloud.deploy_status != consts.DEPLOY_STATE_DONE:
                    LOG.warning("Subcloud %s can be managed only when"
                                "deploy_status is complete" % subcloud_id)
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Subcloud can be managed only if deploy status is complete')
                if subcloud.availability_status != \
                        consts.AVAILABILITY_ONLINE:
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
                                          group_id=group_id)

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

            if management_state == consts.MANAGEMENT_UNMANAGED:

                # set all endpoint statuses to unknown
                self.update_subcloud_endpoint_status(
                    context,
                    subcloud_name=subcloud.name,
                    endpoint_type=None,
                    sync_status=consts.SYNC_STATUS_UNKNOWN)

        return db_api.subcloud_db_model_to_dict(subcloud)

    def _update_online_managed_subcloud(self, context, subcloud_id,
                                        endpoint_type, sync_status,
                                        alarmable):
        """Update online/managed subcloud endpoint status

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        """

        subcloud_status_list = []
        subcloud = None
        # retrieve the info from the db for this subcloud.
        # subcloud_id should not be None
        try:
            for subcloud, subcloud_status in db_api. \
                    subcloud_get_with_status(context, subcloud_id):
                if subcloud_status:
                    subcloud_status_list.append(
                        db_api.subcloud_endpoint_status_db_model_to_dict(
                            subcloud_status))
        except Exception as e:
            LOG.exception(e)
            raise e

        if subcloud:
            if endpoint_type:
                # updating a single endpoint on a single subcloud
                for subcloud_status in subcloud_status_list:
                    if subcloud_status['endpoint_type'] == endpoint_type:
                        if subcloud_status['sync_status'] == sync_status:
                            # No change in the sync_status
                            LOG.debug("Sync status (%s) for subcloud %s did "
                                      "not change - ignore update" %
                                      (sync_status, subcloud.name))
                            return
                        # We found the endpoint
                        break
                else:
                    # We did not find the endpoint
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Endpoint %s not found for subcloud' %
                            endpoint_type)

                LOG.info("Updating subcloud:%s endpoint:%s sync:%s" %
                         (subcloud.name, endpoint_type, sync_status))
                db_api.subcloud_status_update(context,
                                              subcloud_id,
                                              endpoint_type,
                                              sync_status)

                entity_instance_id = "subcloud=%s.resource=%s" % \
                                     (subcloud.name, endpoint_type)
                fault = self.fm_api.get_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                    entity_instance_id)

                if (sync_status != consts.SYNC_STATUS_OUT_OF_SYNC) \
                        and fault:
                    try:
                        self.fm_api.clear_fault(
                            fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
                            entity_instance_id)
                    except Exception as e:
                        LOG.exception(e)

                elif not fault and alarmable and \
                        (sync_status == consts.SYNC_STATUS_OUT_OF_SYNC):
                    entity_type_id = fm_const.FM_ENTITY_TYPE_SUBCLOUD
                    try:
                        fault = fm_api.Fault(
                            alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
                            alarm_state=fm_const.FM_ALARM_STATE_SET,
                            entity_type_id=entity_type_id,
                            entity_instance_id=entity_instance_id,
                            severity=fm_const.FM_ALARM_SEVERITY_MAJOR,
                            reason_text=("%s %s sync_status is "
                                         "out-of-sync" %
                                         (subcloud.name, endpoint_type)),
                            alarm_type=fm_const.FM_ALARM_TYPE_0,
                            probable_cause=fm_const.ALARM_PROBABLE_CAUSE_2,
                            proposed_repair_action="If problem persists "
                                                   "contact next level "
                                                   "of support",
                            service_affecting=False)

                        self.fm_api.set_fault(fault)

                    except Exception as e:
                        LOG.exception(e)

            else:
                # update all endpoints on this subcloud
                LOG.info("Updating all subclouds, endpoint: %s sync: %s" %
                         (endpoint_type, sync_status))

                for entry in subcloud_status_list:
                    endpoint = entry[consts.ENDPOINT_TYPE]
                    db_api.subcloud_status_update(context,
                                                  subcloud_id,
                                                  endpoint,
                                                  sync_status)

                    entity_instance_id = "subcloud=%s.resource=%s" % \
                                         (subcloud.name, endpoint)

                    fault = self.fm_api.get_fault(
                        fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                        entity_instance_id)

                    if (sync_status != consts.SYNC_STATUS_OUT_OF_SYNC) \
                            and fault:
                        try:
                            self.fm_api.clear_fault(
                                fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
                                entity_instance_id)
                        except Exception as e:
                            LOG.exception(e)

                    elif not fault and alarmable and \
                            (sync_status == consts.SYNC_STATUS_OUT_OF_SYNC):
                        entity_type_id = fm_const.FM_ENTITY_TYPE_SUBCLOUD
                        try:
                            fault = fm_api.Fault(
                                alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
                                alarm_state=fm_const.FM_ALARM_STATE_SET,
                                entity_type_id=entity_type_id,
                                entity_instance_id=entity_instance_id,
                                severity=fm_const.FM_ALARM_SEVERITY_MAJOR,
                                reason_text=("%s %s sync_status is "
                                             "out-of-sync" %
                                             (subcloud.name, endpoint)),
                                alarm_type=fm_const.FM_ALARM_TYPE_0,
                                probable_cause=fm_const.ALARM_PROBABLE_CAUSE_2,
                                proposed_repair_action="If problem persists "
                                                       "contact next level "
                                                       "of support",
                                service_affecting=False)

                            self.fm_api.set_fault(fault)
                        except Exception as e:
                            LOG.exception(e)

        else:
            LOG.error("Subcloud not found:%s" % subcloud_id)

    @sync_update_subcloud_endpoint_status
    def _update_subcloud_endpoint_status(
            self, context,
            subcloud_name,
            endpoint_type=None,
            sync_status=consts.SYNC_STATUS_OUT_OF_SYNC,
            alarmable=True):
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_name: name of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        """

        if not subcloud_name:
            raise exceptions.BadRequest(
                resource='subcloud',
                msg='Subcloud name not provided')

        try:
            subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Only allow updating the sync status if managed and online.
        # This means if a subcloud is going offline or unmanaged, then
        # the sync status update must be done first.
        if (((subcloud.availability_status ==
              consts.AVAILABILITY_ONLINE)
            and (subcloud.management_state ==
                 consts.MANAGEMENT_MANAGED))
                or (sync_status != consts.SYNC_STATUS_IN_SYNC)):

            # update a single subcloud
            try:
                self._update_online_managed_subcloud(context,
                                                     subcloud.id,
                                                     endpoint_type,
                                                     sync_status,
                                                     alarmable)
            except Exception as e:
                LOG.exception(e)
                raise e
        else:
            LOG.info("Ignoring unmanaged/offline subcloud sync_status "
                     "update for subcloud:%s endpoint:%s sync:%s" %
                     (subcloud_name, endpoint_type, sync_status))

    def update_subcloud_endpoint_status(
            self, context,
            subcloud_name=None,
            endpoint_type=None,
            sync_status=consts.SYNC_STATUS_OUT_OF_SYNC,
            alarmable=True):
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_name: name of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        """

        if subcloud_name:
            self._update_subcloud_endpoint_status(
                context, subcloud_name, endpoint_type, sync_status, alarmable)
        else:
            # update all subclouds
            for subcloud in db_api.subcloud_get_all(context):
                self._update_subcloud_endpoint_status(
                    context, subcloud.name, endpoint_type, sync_status,
                    alarmable)

    def _update_subcloud_state(self, context, subcloud_name,
                               management_state, availability_status):
        try:
            self.dcorch_rpc_client.update_subcloud_states(
                context, subcloud_name, management_state, availability_status)

            LOG.info('Notifying dcorch, subcloud:%s management: %s, '
                     'availability:%s' %
                     (subcloud_name,
                      management_state,
                      availability_status))
        except Exception:
            LOG.exception('Problem informing dcorch of subcloud state change,'
                          'subcloud: %s' % subcloud_name)

    def _raise_or_clear_subcloud_status_alarm(self, subcloud_name,
                                              availability_status):
        entity_instance_id = "subcloud=%s" % subcloud_name
        fault = self.fm_api.get_fault(
            fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
            entity_instance_id)

        if fault and (availability_status == consts.AVAILABILITY_ONLINE):
            try:
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                    entity_instance_id)
            except Exception:
                LOG.exception("Failed to clear offline alarm for subcloud: %s",
                              subcloud_name)

        elif not fault and \
                (availability_status == consts.AVAILABILITY_OFFLINE):
            try:
                fault = fm_api.Fault(
                    alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                    alarm_state=fm_const.FM_ALARM_STATE_SET,
                    entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
                    entity_instance_id=entity_instance_id,

                    severity=fm_const.FM_ALARM_SEVERITY_CRITICAL,
                    reason_text=('%s is offline' % subcloud_name),
                    alarm_type=fm_const.FM_ALARM_TYPE_0,
                    probable_cause=fm_const.ALARM_PROBABLE_CAUSE_29,
                    proposed_repair_action="Wait for subcloud to "
                                           "become online; if "
                                           "problem persists contact "
                                           "next level of support.",
                    service_affecting=True)

                self.fm_api.set_fault(fault)
            except Exception:
                LOG.exception("Failed to raise offline alarm for subcloud: %s",
                              subcloud_name)

    def update_subcloud_availability(self, context, subcloud_name,
                                     availability_status,
                                     update_state_only=False,
                                     audit_fail_count=None):
        try:
            subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
        except Exception:
            LOG.exception("Failed to get subcloud by name: %s" % subcloud_name)

        if update_state_only:
            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit. Get the most up-to-date data.
            self._update_subcloud_state(context, subcloud_name,
                                        subcloud.management_state,
                                        availability_status)
        elif availability_status is None:
            # only update the audit fail count
            try:
                db_api.subcloud_update(self.context, subcloud.id,
                                       audit_fail_count=audit_fail_count)
            except exceptions.SubcloudNotFound:
                # slim possibility subcloud could have been deleted since
                # we found it in db, ignore this benign error.
                LOG.info('Ignoring SubcloudNotFound when attempting '
                         'audit_fail_count update: %s' % subcloud_name)
                return
        else:
            self._raise_or_clear_subcloud_status_alarm(subcloud_name,
                                                       availability_status)

            if availability_status == consts.AVAILABILITY_OFFLINE:
                # Subcloud is going offline, set all endpoint statuses to
                # unknown.
                self._update_subcloud_endpoint_status(
                    context, subcloud_name, endpoint_type=None,
                    sync_status=consts.SYNC_STATUS_UNKNOWN)

            try:
                updated_subcloud = db_api.subcloud_update(
                    context,
                    subcloud.id,
                    availability_status=availability_status,
                    audit_fail_count=audit_fail_count)
            except exceptions.SubcloudNotFound:
                # slim possibility subcloud could have been deleted since
                # we found it in db, ignore this benign error.
                LOG.info('Ignoring SubcloudNotFound when attempting state'
                         ' update: %s' % subcloud_name)
                return

            # Send dcorch a state update
            self._update_subcloud_state(context, subcloud_name,
                                        updated_subcloud.management_state,
                                        availability_status)

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
