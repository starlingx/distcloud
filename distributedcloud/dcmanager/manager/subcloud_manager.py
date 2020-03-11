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

from oslo_log import log as logging
from oslo_messaging import RemoteError

from tsconfig.tsconfig import CONFIG_PATH
from tsconfig.tsconfig import SW_VERSION

from dcorch.common import consts as dcorch_consts
from dcorch.drivers.openstack.keystone_v3 import KeystoneClient
from dcorch.rpc import client as dcorch_rpc_client

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.drivers.openstack.sysinv_v1 import SysinvClient
from dcmanager.manager.subcloud_install import SubcloudInstall

from fm_api import constants as fm_const
from fm_api import fm_api

LOG = logging.getLogger(__name__)

# Name of our distributed cloud addn_hosts file for dnsmasq
# to read.  This file is referenced in dnsmasq.conf
ADDN_HOSTS_DC = 'dnsmasq.addn_hosts_dc'

# Subcloud configuration paths
ANSIBLE_OVERRIDES_PATH = '/opt/dc/ansible'
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

    def add_subcloud(self, context, payload):
        """Add subcloud and notify orchestrators.

        :param context: request context object
        :param name: name of subcloud to add
        :param payload: subcloud configuration
        """
        LOG.info("Adding subcloud %s." % payload['name'])
        dcorch_populated = False
        try:
            subcloud = db_api.subcloud_get_by_name(context, payload['name'])
        except exceptions.SubcloudNameNotFound:
            pass
        else:
            raise exceptions.BadRequest(
                resource='subcloud',
                msg='Subcloud with that name already exists')

        # Subcloud is added with software version that matches system
        # controller.
        software_version = SW_VERSION
        try:
            subcloud = db_api.subcloud_create(
                context,
                payload['name'],
                payload.get('description'),
                payload.get('location'),
                software_version,
                payload['management_subnet'],
                payload['management_gateway_address'],
                payload['management_start_address'],
                payload['management_end_address'],
                payload['systemcontroller_gateway_address'],
                consts.DEPLOY_STATE_NONE,
                False)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Populate the subcloud status table with all endpoints
        for endpoint in dcorch_consts.ENDPOINT_TYPES_LIST:
            db_api.subcloud_status_create(context,
                                          subcloud.id,
                                          endpoint)

        try:
            # Ansible inventory filename for the specified subcloud
            ansible_subcloud_inventory_file = os.path.join(
                ANSIBLE_OVERRIDES_PATH,
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
                    endpoint_url = "http://{}:6385/v1".format(endpoint_ip)
                    endpoint_config.append((service.id, endpoint_url))
                if service.type == dcorch_consts.ENDPOINT_TYPE_IDENTITY:
                    endpoint_url = "http://{}:5000/v3".format(endpoint_ip)
                    endpoint_config.append((service.id, endpoint_url))
                if service.type == dcorch_consts.ENDPOINT_TYPE_PATCHING:
                    endpoint_url = "http://{}:5491".format(endpoint_ip)
                    endpoint_config.append((service.id, endpoint_url))
                if service.type == dcorch_consts.ENDPOINT_TYPE_FM:
                    endpoint_url = "http://{}:18002".format(endpoint_ip)
                    endpoint_config.append((service.id, endpoint_url))
                if service.type == dcorch_consts.ENDPOINT_TYPE_NFV:
                    endpoint_url = "http://{}:4545".format(endpoint_ip)
                    endpoint_config.append((service.id, endpoint_url))

            if len(endpoint_config) < 5:
                raise exceptions.BadRequest(
                    resource='subcloud',
                    msg='Missing service in SystemController')

            for endpoint in endpoint_config:
                for iface in ['internal', 'admin']:
                    m_ks_client.keystone_client.endpoints.create(
                        endpoint[0],
                        endpoint[1],
                        interface=iface,
                        region=subcloud.name)

            # Inform orchestrator that subcloud has been added
            self.dcorch_rpc_client.add_subcloud(
                context, subcloud.name, subcloud.software_version)
            dcorch_populated = True

            # Regenerate the addn_hosts_dc file
            self._create_addn_hosts_dc(context)

            # Query system controller keystone admin user/project IDs and
            # store in payload so they get copied to the override file
            admin_user = m_ks_client.get_user_by_name('admin')
            admin_project = m_ks_client.get_project_by_name('admin')
            payload['system_controller_keystone_admin_user_id'] = \
                admin_user.id
            payload['system_controller_keystone_admin_project_id'] = \
                admin_project.id

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
                payload['deploy_values']['ansible_become_pass'] = \
                    payload['sysadmin_password']
                payload['deploy_values']['ansible_ssh_pass'] = \
                    payload['sysadmin_password']
                payload['deploy_values']['admin_password'] = \
                    str(keyring.get_password('CGCS', 'admin'))

            del payload['sysadmin_password']

            payload['users'] = dict()
            for user in USERS_TO_REPLICATE:
                payload['users'][user] = \
                    str(keyring.get_password(user, SERVICES_USER))

            # Create the ansible inventory for the new subcloud
            self._create_subcloud_inventory(payload,
                                            ansible_subcloud_inventory_file)

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
                    "-e", "@%s" % ANSIBLE_OVERRIDES_PATH + "/" +
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
                    ANSIBLE_OVERRIDES_PATH, subcloud.name)]

            deploy_command = None
            if "deploy_playbook" in payload:
                deploy_command = [
                    "ansible-playbook", ANSIBLE_OVERRIDES_PATH + '/' +
                    payload['name'] + "_deploy.yml",
                    "-e", "@%s" % ANSIBLE_OVERRIDES_PATH + "/" +
                          payload['name'] + "_deploy_values.yml",
                    "-i",
                    ansible_subcloud_inventory_file,
                    "--limit", subcloud.name
                ]

            apply_thread = threading.Thread(
                target=self.run_deploy,
                args=(install_command, apply_command, deploy_command, subcloud,
                      payload, context))
            apply_thread.start()

            return db_api.subcloud_db_model_to_dict(subcloud)

        except Exception as e:
            LOG.exception(e)
            # If we failed to create the subcloud, clean up anything we may
            # have done.
            self._remove_subcloud_details(context,
                                          subcloud,
                                          ansible_subcloud_inventory_file,
                                          dcorch_populated)
            raise e

    @staticmethod
    def run_deploy(install_command, apply_command, deploy_command, subcloud,
                   payload, context):

        if install_command:
            db_api.subcloud_update(
                context, subcloud.id,
                deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)
            try:
                install = SubcloudInstall(context, subcloud.name)
                install.prep(ANSIBLE_OVERRIDES_PATH, payload['install_values'])
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

        overrides_file = os.path.join(ANSIBLE_OVERRIDES_PATH,
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
                             'install_values']:
                    f_out_overrides_file.write("%s: %s\n" % (k, json.dumps(v)))

    def _write_deploy_files(self, payload):
        """Create the deploy playbook and value files for the subcloud"""

        deploy_playbook_file = os.path.join(
            ANSIBLE_OVERRIDES_PATH, payload['name'] + '_deploy.yml')
        deploy_values_file = os.path.join(
            ANSIBLE_OVERRIDES_PATH, payload['name'] + '_deploy_values.yml')

        with open(deploy_playbook_file, 'w') as f_out_deploy_playbook_file:
            json.dump(payload['deploy_playbook'], f_out_deploy_playbook_file)
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

    def _remove_subcloud_details(self, context,
                                 subcloud,
                                 ansible_subcloud_inventory_file,
                                 dcorch_populated=True):
        """Remove subcloud details from database and inform orchestrators"""
        # Inform orchestrators that subcloud has been deleted
        if dcorch_populated:
            try:
                self.dcorch_rpc_client.del_subcloud(context, subcloud.name)
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
            ANSIBLE_OVERRIDES_PATH,
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

    def update_subcloud(self, context, subcloud_id, management_state=None,
                        description=None, location=None):
        """Update subcloud and notify orchestrators.

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param management_state: new management state
        :param description: new description
        :param location: new location
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
                if subcloud.availability_status != \
                        consts.AVAILABILITY_ONLINE:
                    LOG.warning("Subcloud %s is not online" % subcloud_id)
                    raise exceptions.SubcloudNotOnline()
            else:
                LOG.error("Invalid management_state %s" % management_state)
                raise exceptions.InternalError()

        subcloud = db_api.subcloud_update(context, subcloud_id,
                                          management_state=management_state,
                                          description=description,
                                          location=location)

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
