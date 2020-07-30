# Copyright (c) 2017 Ericsson AB.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from requests_toolbelt.multipart import decoder

import base64
import json
import keyring
from netaddr import AddrFormatError
from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange
import os
from oslo_config import cfg
from oslo_log import log as logging
from oslo_messaging import RemoteError
import yaml

import pecan
from pecan import expose
from pecan import request

from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions
from dccommon import install_consts

from keystoneauth1 import exceptions as keystone_exceptions

import tsconfig.tsconfig as tsc

from dcmanager.api.controllers import restcomm
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api

from dcmanager.rpc import client as rpc_client
from dcorch.common import consts as dcorch_consts

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
# System mode
SYSTEM_MODE_DUPLEX = "duplex"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX_DIRECT = "duplex-direct"

LOCK_NAME = 'SubcloudsController'

BOOTSTRAP_VALUES = 'bootstrap_values'
INSTALL_VALUES = 'install_values'

SUBCLOUD_ADD_MANDATORY_FILE = [
    BOOTSTRAP_VALUES,
]

SUBCLOUD_RECONFIG_MANDATORY_FILE = [
    consts.DEPLOY_CONFIG,
]

SUBCLOUD_ADD_GET_FILE_CONTENTS = [
    BOOTSTRAP_VALUES,
    INSTALL_VALUES,
]


class SubcloudsController(object):
    VERSION_ALIASES = {
        'Newton': '1.0',
    }

    def __init__(self):
        super(SubcloudsController, self).__init__()
        self.rpc_client = rpc_client.ManagerClient()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    def _validate_group_id(self, context, group_id):
        try:
            # The DB API will raise an exception if the group_id is invalid
            db_api.subcloud_group_get(context, group_id)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(400, _("Invalid group_id"))

    @staticmethod
    def _get_common_deploy_files(payload):
        for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
            filename = None
            dir_path = tsc.DEPLOY_PATH
            if os.path.isdir(dir_path):
                filename = utils.get_filename_by_prefix(dir_path, f + '_')
            if filename is None:
                pecan.abort(400, _("Missing required deploy file for %s") % f)
            payload.update({f: os.path.join(dir_path, filename)})

    def _upload_deploy_config_file(self, request, payload):
        if consts.DEPLOY_CONFIG in request.POST:
            file_item = request.POST[consts.DEPLOY_CONFIG]
            filename = getattr(file_item, 'filename', '')
            if not filename:
                pecan.abort(400, _("No %s file uploaded"
                            % consts.DEPLOY_CONFIG))
            file_item.file.seek(0, os.SEEK_SET)
            contents = file_item.file.read()
            # the deploy config needs to upload to the override location
            fn = os.path.join(consts.ANSIBLE_OVERRIDES_PATH, payload['name']
                              + '_deploy_config.yml')
            try:
                with open(fn, "w") as f:
                    f.write(contents)
            except Exception:
                msg = _("Failed to upload %s file" % consts.DEPLOY_CONFIG)
                LOG.exception(msg)
                pecan.abort(400, msg)
            payload.update({consts.DEPLOY_CONFIG: fn})
            self._get_common_deploy_files(payload)

    @staticmethod
    def _get_request_data(request):
        payload = dict()
        for f in SUBCLOUD_ADD_MANDATORY_FILE:
            if f not in request.POST:
                pecan.abort(400, _("Missing required file for %s") % f)

        for f in SUBCLOUD_ADD_GET_FILE_CONTENTS:
            if f in request.POST:
                file_item = request.POST[f]
                file_item.file.seek(0, os.SEEK_SET)
                data = yaml.safe_load(file_item.file.read().decode('utf8'))
                if f == BOOTSTRAP_VALUES:
                    payload.update(data)
                else:
                    payload.update({f: data})
                del request.POST[f]
        payload.update(request.POST)
        return payload

    @staticmethod
    def _get_patch_data(request):
        fields = ['management-state', 'description', 'location', 'group_id',
                  'bmc_password', INSTALL_VALUES, 'force']
        payload = dict()
        multipart_data = decoder.MultipartDecoder(
            request.body, pecan.request.headers.get('Content-Type'))
        for f in fields:
            for part in multipart_data.parts:
                header = part.headers.get('Content-Disposition')
                if f in header:
                    data = yaml.safe_load(part.content.decode('utf8'))
                    payload.update({f: data})
        return payload

    @staticmethod
    def _get_reconfig_payload(request, subcloud_name):
        payload = dict()
        multipart_data = decoder.MultipartDecoder(request.body,
                                                  pecan.request.headers.get('Content-Type'))

        for filename in SUBCLOUD_RECONFIG_MANDATORY_FILE:
            for part in multipart_data.parts:
                header = part.headers.get('Content-Disposition')
                if filename in header:
                    file_item = part.content
                    fn = os.path.join(consts.ANSIBLE_OVERRIDES_PATH, subcloud_name
                                      + '_deploy_config.yml')
                    try:
                        with open(fn, "w") as f:
                            f.write(file_item)
                    except Exception:
                        msg = _("Failed to upload %s file" % consts.DEPLOY_CONFIG)
                        LOG.exception(msg)
                        pecan.abort(400, msg)
                    payload.update({consts.DEPLOY_CONFIG: fn})
                elif "sysadmin_password" in header:
                    payload.update({'sysadmin_password': part.content})
        SubcloudsController._get_common_deploy_files(payload)
        return payload

    @staticmethod
    def _get_updatestatus_payload(request):
        """retrieve payload of a patch request for update_status

        :param request: request from the http client
        :return: dict object submitted from the http client
        """

        payload = dict()
        payload.update(json.loads(request.body))
        return payload

    def _validate_subcloud_config(self,
                                  context,
                                  name,
                                  management_subnet_str,
                                  management_start_ip_str,
                                  management_end_ip_str,
                                  management_gateway_ip_str,
                                  external_oam_subnet_str,
                                  external_oam_gateway_address_str,
                                  external_oam_floating_address_str,
                                  systemcontroller_gateway_ip_str,
                                  group_id):
        """Check whether subcloud config is valid."""

        # Validate the name
        if name.isdigit():
            pecan.abort(400, _("name must contain alphabetic characters"))

        if name in [consts.DEFAULT_REGION_NAME,
                    consts.SYSTEM_CONTROLLER_NAME]:
            pecan.abort(400, _("name cannot be %(bad_name1)s or %(bad_name2)s")
                        % {'bad_name1': consts.DEFAULT_REGION_NAME,
                           'bad_name2': consts.SYSTEM_CONTROLLER_NAME})

        # Parse/validate the management subnet
        subcloud_subnets = []
        subclouds = db_api.subcloud_get_all(context)
        for subcloud in subclouds:
            subcloud_subnets.append(IPNetwork(subcloud.management_subnet))

        MIN_MANAGEMENT_SUBNET_SIZE = 8
        # subtract 3 for network, gateway and broadcast addresses.
        MIN_MANAGEMENT_ADDRESSES = MIN_MANAGEMENT_SUBNET_SIZE - 3

        management_subnet = None
        try:
            management_subnet = utils.validate_network_str(
                management_subnet_str,
                minimum_size=MIN_MANAGEMENT_SUBNET_SIZE,
                existing_networks=subcloud_subnets)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_subnet invalid: %s") % e)

        # Parse/validate the start/end addresses
        management_start_ip = None
        try:
            management_start_ip = utils.validate_address_str(
                management_start_ip_str, management_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_start_address invalid: %s") % e)

        management_end_ip = None
        try:
            management_end_ip = utils.validate_address_str(
                management_end_ip_str, management_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_end_address invalid: %s") % e)

        if not management_start_ip < management_end_ip:
            pecan.abort(
                400,
                _("management_start_address  not less than "
                  "management_end_address"))

        if not len(IPRange(management_start_ip, management_end_ip)) >= \
                MIN_MANAGEMENT_ADDRESSES:
            pecan.abort(
                400,
                _("management address range must contain at least %d "
                  "addresses") % MIN_MANAGEMENT_ADDRESSES)

        # Parse/validate the gateway
        try:
            utils.validate_address_str(
                management_gateway_ip_str, management_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_gateway_address invalid: %s") % e)

        # Ensure subcloud management gateway is not within the actual subcloud
        # management subnet address pool for consistency with the
        # systemcontroller gateway restriction below. Address collision
        # is not a concern as the address is added to sysinv.
        subcloud_mgmt_address_start = IPAddress(management_start_ip_str)
        subcloud_mgmt_address_end = IPAddress(management_end_ip_str)
        subcloud_mgmt_gw_ip = IPAddress(management_gateway_ip_str)
        if ((subcloud_mgmt_gw_ip >= subcloud_mgmt_address_start) and
                (subcloud_mgmt_gw_ip <= subcloud_mgmt_address_end)):
            pecan.abort(400, _("management_gateway_address invalid, "
                               "is within management pool: %(start)s - "
                               "%(end)s") %
                        {'start': subcloud_mgmt_address_start,
                         'end': subcloud_mgmt_address_end})

        # Ensure systemcontroller gateway is in the management subnet
        # for the systemcontroller region.
        management_address_pool = self._get_management_address_pool(context)
        systemcontroller_subnet_str = "%s/%d" % (
            management_address_pool.network,
            management_address_pool.prefix)
        systemcontroller_subnet = IPNetwork(systemcontroller_subnet_str)
        try:
            utils.validate_address_str(
                systemcontroller_gateway_ip_str, systemcontroller_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400,
                        _("systemcontroller_gateway_address invalid: %s") % e)
        # Ensure systemcontroller gateway is not within the actual
        # management subnet address pool to prevent address collision.
        mgmt_address_start = IPAddress(management_address_pool.ranges[0][0])
        mgmt_address_end = IPAddress(management_address_pool.ranges[0][1])
        systemcontroller_gw_ip = IPAddress(systemcontroller_gateway_ip_str)
        if ((systemcontroller_gw_ip >= mgmt_address_start) and
                (systemcontroller_gw_ip <= mgmt_address_end)):
            pecan.abort(400, _("systemcontroller_gateway_address invalid, "
                               "is within management pool: %(start)s - "
                               "%(end)s") %
                        {'start': mgmt_address_start, 'end': mgmt_address_end})

        # Parse/validate the oam subnet
        MIN_OAM_SUBNET_SIZE = 3
        oam_subnet = None
        try:
            oam_subnet = utils.validate_network_str(
                external_oam_subnet_str,
                minimum_size=MIN_OAM_SUBNET_SIZE,
                existing_networks=subcloud_subnets)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("external_oam_subnet invalid: %s") % e)

        # Parse/validate the addresses
        try:
            utils.validate_address_str(
                external_oam_gateway_address_str, oam_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("oam_gateway_address invalid: %s") % e)

        try:
            utils.validate_address_str(
                external_oam_floating_address_str, oam_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("oam_floating_address invalid: %s") % e)
        self._validate_group_id(context, group_id)

    @staticmethod
    def _validate_install_values(payload):
        install_values = payload.get('install_values')
        bmc_password = payload.get('bmc_password')
        if not bmc_password:
            pecan.abort(400, _('subcloud bmc_password required'))
        try:
            base64.b64decode(bmc_password).decode('utf-8')
        except Exception:
            msg = _('Failed to decode subcloud bmc_password, verify'
                    ' the password is base64 encoded')
            LOG.exception(msg)
            pecan.abort(400, msg)
        payload['install_values'].update({'bmc_password': bmc_password})

        for k in install_consts.MANDATORY_INSTALL_VALUES:
            if k not in install_values:
                pecan.abort(400, _('Mandatory install value %s not present')
                            % k)

        if (install_values['install_type'] not in
                range(install_consts.SUPPORTED_INSTALL_TYPES)):
            pecan.abort(400, _("install_type invalid: %s") %
                        install_values['install_type'])

        try:
            ip_version = (IPAddress(install_values['bootstrap_address']).
                          version)
        except AddrFormatError as e:
            LOG.exception(e)
            pecan.abort(400, _("bootstrap_address invalid: %s") % e)

        try:
            bmc_address = IPAddress(install_values['bmc_address'])
        except AddrFormatError as e:
            LOG.exception(e)
            pecan.abort(400, _("bmc_address invalid: %s") % e)

        if bmc_address.version != ip_version:
            pecan.abort(400, _("bmc_address and bootstrap_address "
                               "must be the same IP version"))

        if 'nexthop_gateway' in install_values:
            try:
                gateway_ip = IPAddress(install_values['nexthop_gateway'])
            except AddrFormatError as e:
                LOG.exception(e)
                pecan.abort(400, _("nexthop_gateway address invalid: %s") % e)
            if gateway_ip.version != ip_version:
                pecan.abort(400, _("nexthop_gateway and bootstrap_address "
                                   "must be the same IP version"))

        if ('network_address' in install_values and
                'nexthop_gateway' not in install_values):
            pecan.abort(400, _("nexthop_gateway is required when "
                               "network_address is present"))

        if 'nexthop_gateway' and 'network_address' in install_values:
            if 'network_mask' not in install_values:
                pecan.abort(400, _("The network mask is required when network "
                                   "address is present"))

            network_str = (install_values['network_address'] + '/' +
                           str(install_values['network_mask']))
            try:
                network = utils.validate_network_str(network_str, 1)
            except exceptions.ValidateFail as e:
                LOG.exception(e)
                pecan.abort(400, _("network address invalid: %s") % e)

            if network.version != ip_version:
                pecan.abort(400, _("network address and bootstrap address "
                                   "must be the same IP version"))

    def _get_subcloud_users(self):
        """Get the subcloud users and passwords from keyring"""
        DEFAULT_SERVICE_PROJECT_NAME = 'services'
        # First entry is openstack user name, second entry is the user stored
        # in keyring. Not sure why heat_admin uses a different keystone name.
        SUBCLOUD_USERS = [
            ('sysinv', 'sysinv'),
            ('patching', 'patching'),
            ('vim', 'vim'),
            ('mtce', 'mtce'),
            ('fm', 'fm'),
            ('barbican', 'barbican'),
            ('smapi', 'smapi'),
            ('dcdbsync', 'dcdbsync')
        ]

        user_list = list()
        for user in SUBCLOUD_USERS:
            password = keyring.get_password(user[1],
                                            DEFAULT_SERVICE_PROJECT_NAME)
            if password:
                user_dict = dict()
                user_dict['name'] = user[0]
                user_dict['password'] = password
                user_list.append(user_dict)
            else:
                LOG.error("User %s not found in keyring as %s" % (user[0],
                                                                  user[1]))
                pecan.abort(500, _('System configuration error'))

        return user_list

    def _get_management_address_pool(self, context):
        """Get the system controller's management address pool"""
        session = KeystoneClient().endpoint_cache.get_session_from_token(
            context.auth_token, context.project)
        sysinv_client = SysinvClient(consts.DEFAULT_REGION_NAME, session)
        return sysinv_client.get_management_address_pool()

    @staticmethod
    def get_ks_client(region_name=None):
        """This will get a new keystone client (and new token)"""
        try:
            return KeystoneClient(region_name)
        except Exception:
            LOG.warn('Failure initializing KeystoneClient '
                     'for region %s' % region_name)
            raise

    def _get_oam_addresses(self, context, subcloud_name):
        """Get the subclouds oam addresses"""

        # First need to retrieve the Subcloud's Keystone session
        try:
            sc_ks_client = self.get_ks_client(subcloud_name)
            sysinv_client = SysinvClient(subcloud_name,
                                         sc_ks_client.session)
            return sysinv_client.get_oam_addresses()
        except (keystone_exceptions.EndpointNotFound, IndexError) as e:
            message = ("Identity endpoint for subcloud: %s not found. %s" %
                       (subcloud_name, e))
            LOG.error(message)
        except dccommon_exceptions.OAMAddressesNotFound:
            message = ("OAM addresses for subcloud: %s not found." %
                       (subcloud_name))
            LOG.error(message)
        return None

    def _add_subcloud_to_database(self, context, payload):
        try:
            db_api.subcloud_get_by_name(context, payload['name'])
        except exceptions.SubcloudNameNotFound:
            pass
        else:
            raise exceptions.BadRequest(
                resource='subcloud',
                msg='Subcloud with that name already exists')

        # Subcloud is added with software version that matches system
        # controller.
        software_version = tsc.SW_VERSION
        # if group_id has been omitted from payload, use 'Default'.
        group_id = payload.get('group_id',
                               consts.DEFAULT_SUBCLOUD_GROUP_ID)
        data_install = None
        if 'install_values' in payload:
            data_install = json.dumps(payload['install_values'])

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
            False,
            group_id,
            data_install=data_install)
        return subcloud

    @index.when(method='GET', template='json')
    def get(self, subcloud_ref=None, detail=None):
        """Get details about subcloud.

        :param subcloud_ref: ID or name of subcloud
        """
        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:
            # List of subclouds requested
            subclouds = db_api.subcloud_get_all_with_status(context)
            result = dict()
            result['subclouds'] = []
            first_time = True
            subcloud_list = []
            subcloud_status_list = []

            # We get back a subcloud, subcloud_status pair for every
            # subcloud_status entry corresponding to a subcloud.  (Subcloud
            # info repeats)
            # Aggregate all the sync status for each of the
            # endpoints per subcloud into an overall sync status
            for subcloud, subcloud_status in subclouds:
                subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
                subcloud_status_dict = db_api.subcloud_status_db_model_to_dict(
                    subcloud_status)
                subcloud_dict.update(subcloud_status_dict)

                if not first_time:
                    if subcloud_list[-1]['id'] == subcloud_dict['id']:
                        # We have a match for this subcloud id already,
                        # check if we have a same sync_status
                        if subcloud_list[-1][consts.SYNC_STATUS] != \
                                subcloud_dict[consts.SYNC_STATUS]:
                            subcloud_list[-1][consts.SYNC_STATUS] = \
                                consts.SYNC_STATUS_OUT_OF_SYNC

                        if subcloud_status:
                            subcloud_status_list.append(
                                db_api.subcloud_endpoint_status_db_model_to_dict(  # noqa
                                    subcloud_status))
                        subcloud_list[-1][
                            consts.ENDPOINT_SYNC_STATUS] = subcloud_status_list

                    else:
                        subcloud_status_list = []
                        if subcloud_status:
                            subcloud_status_list.append(
                                db_api.subcloud_endpoint_status_db_model_to_dict(  # noqa
                                    subcloud_status))

                        subcloud_list.append(subcloud_dict)
                else:
                    if subcloud_status:
                        subcloud_status_list.append(
                            db_api.subcloud_endpoint_status_db_model_to_dict(
                                subcloud_status))
                    subcloud_list.append(subcloud_dict)

                first_time = False

            for s in subcloud_list:
                result['subclouds'].append(s)

            return result
        else:
            # Single subcloud requested
            subcloud = None
            subcloud_dict = dict()
            subcloud_status_list = []
            endpoint_sync_dict = dict()

            if subcloud_ref.isdigit():
                # Look up subcloud as an ID
                try:
                    subcloud = db_api.subcloud_get(context, subcloud_ref)
                except exceptions.SubcloudNotFound:
                    pecan.abort(404, _('Subcloud not found'))
            else:
                # Look up subcloud by name
                try:
                    subcloud = db_api.subcloud_get_by_name(context,
                                                           subcloud_ref)
                except exceptions.SubcloudNameNotFound:
                    pecan.abort(404, _('Subcloud not found'))

            subcloud_id = subcloud.id

            # Data for this subcloud requested
            # Build up and append a dictionary of the endpoints
            # sync status to the result.
            for subcloud, subcloud_status in db_api. \
                    subcloud_get_with_status(context, subcloud_id):
                subcloud_dict = db_api.subcloud_db_model_to_dict(
                    subcloud)
                # may be empty subcloud_status entry, account for this
                if subcloud_status:
                    subcloud_status_list.append(
                        db_api.subcloud_endpoint_status_db_model_to_dict(
                            subcloud_status))
            endpoint_sync_dict = {consts.ENDPOINT_SYNC_STATUS:
                                  subcloud_status_list}
            subcloud_dict.update(endpoint_sync_dict)

            if detail is not None:
                oam_addresses = self._get_oam_addresses(context,
                                                        subcloud_ref)
                if oam_addresses is not None:
                    oam_floating_ip = oam_addresses.oam_floating_ip
                else:
                    oam_floating_ip = "unavailable"
                floating_ip_dict = {"oam_floating_ip":
                                    oam_floating_ip}
                subcloud_dict.update(floating_ip_dict)

            return subcloud_dict

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self, subcloud_ref=None):
        """Create and deploy a new subcloud.

        :param subcloud_ref: ID of or name subcloud (only used when generating
                             config)
        """

        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:

            payload = self._get_request_data(request)

            if not payload:
                pecan.abort(400, _('Body required'))

            name = payload.get('name')
            if not name:
                pecan.abort(400, _('name required'))

            system_mode = payload.get('system_mode')
            if not system_mode:
                pecan.abort(400, _('system_mode required'))

            management_subnet = payload.get('management_subnet')
            if not management_subnet:
                pecan.abort(400, _('management_subnet required'))

            management_start_ip = payload.get('management_start_address')
            if not management_start_ip:
                pecan.abort(400, _('management_start_address required'))

            management_end_ip = payload.get('management_end_address')
            if not management_end_ip:
                pecan.abort(400, _('management_end_address required'))

            management_gateway_ip = payload.get('management_gateway_address')
            if not management_gateway_ip:
                pecan.abort(400, _('management_gateway_address required'))

            systemcontroller_gateway_ip = \
                payload.get('systemcontroller_gateway_address')
            if not systemcontroller_gateway_ip:
                pecan.abort(400,
                            _('systemcontroller_gateway_address required'))

            external_oam_subnet = payload.get('external_oam_subnet')
            if not external_oam_subnet:
                pecan.abort(400, _('external_oam_subnet required'))

            external_oam_gateway_ip = \
                payload.get('external_oam_gateway_address')
            if not external_oam_gateway_ip:
                pecan.abort(400, _('external_oam_gateway_address required'))

            external_oam_floating_ip = \
                payload.get('external_oam_floating_address')
            if not external_oam_floating_ip:
                pecan.abort(400, _('external_oam_floating_address required'))

            sysadmin_password = \
                payload.get('sysadmin_password')
            if not sysadmin_password:
                pecan.abort(400, _('subcloud sysadmin_password required'))
            try:
                payload['sysadmin_password'] = base64.b64decode(
                    sysadmin_password).decode('utf-8')
            except Exception:
                msg = _('Failed to decode subcloud sysadmin_password, '
                        'verify the password is base64 encoded')
                LOG.exception(msg)
                pecan.abort(400, msg)

            # If a subcloud group is not passed, use the default
            group_id = payload.get('group_id',
                                   consts.DEFAULT_SUBCLOUD_GROUP_ID)

            self._validate_subcloud_config(context,
                                           name,
                                           management_subnet,
                                           management_start_ip,
                                           management_end_ip,
                                           management_gateway_ip,
                                           external_oam_subnet,
                                           external_oam_gateway_ip,
                                           external_oam_floating_ip,
                                           systemcontroller_gateway_ip,
                                           group_id)

            if 'install_values' in payload:
                self._validate_install_values(payload)

            # Upload the deploy config files if it is included in the request
            # It has a dependency on the subcloud name, and it is called after
            # the name has been validated
            self._upload_deploy_config_file(request, payload)

            try:
                # Add the subcloud details to the database
                subcloud = self._add_subcloud_to_database(context, payload)
                # Ask dcmanager-manager to add the subcloud.
                # It will do all the real work...
                self.rpc_client.add_subcloud(context, payload)
                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to create subcloud %s" % name)
                pecan.abort(500, _('Unable to create subcloud'))
        else:
            pecan.abort(400, _('Invalid request'))

    @utils.synchronized(LOCK_NAME)
    @index.when(method='PATCH', template='json')
    def patch(self, subcloud_ref=None, verb=None):
        """Update a subcloud.

        :param subcloud_ref: ID or name of subcloud to update

        :param verb: Specifies the patch action to be taken
        or subcloud update operation
        """

        context = restcomm.extract_context_from_environ()
        subcloud = None

        if subcloud_ref is None:
            pecan.abort(400, _('Subcloud ID required'))

        if subcloud_ref.isdigit():
            # Look up subcloud as an ID
            try:
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            except exceptions.SubcloudNotFound:
                pecan.abort(404, _('Subcloud not found'))
        else:
            # Look up subcloud by name
            try:
                subcloud = db_api.subcloud_get_by_name(context,
                                                       subcloud_ref)
            except exceptions.SubcloudNameNotFound:
                pecan.abort(404, _('Subcloud not found'))

        subcloud_id = subcloud.id

        if verb is None:
            payload = self._get_patch_data(request)
            if not payload:
                pecan.abort(400, _('Body required'))

            management_state = payload.get('management-state')
            description = payload.get('description')
            location = payload.get('location')
            group_id = payload.get('group_id')

            # Syntax checking
            if management_state and \
                    management_state not in [consts.MANAGEMENT_UNMANAGED,
                                             consts.MANAGEMENT_MANAGED]:
                pecan.abort(400, _('Invalid management-state'))

            force_flag = payload.get('force')
            if force_flag is not None:
                if force_flag not in [True, False]:
                    pecan.abort(400, _('Invalid force value'))
                elif management_state != consts.MANAGEMENT_MANAGED:
                    pecan.abort(400, _('Invalid option: force'))

            # Verify the group_id is valid
            if group_id:
                try:
                    db_api.subcloud_group_get(context, group_id)
                except exceptions.SubcloudGroupNotFound:
                    pecan.abort(400, _('Invalid group-id'))

            data_install = None
            if INSTALL_VALUES in payload:
                self._validate_install_values(payload)
                data_install = json.dumps(payload[INSTALL_VALUES])

            try:
                # Inform dcmanager-manager that subcloud has been updated.
                # It will do all the real work...
                subcloud = self.rpc_client.update_subcloud(
                    context, subcloud_id, management_state=management_state,
                    description=description, location=location, group_id=group_id,
                    data_install=data_install, force=force_flag)
                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(500, _('Unable to update subcloud'))
        elif verb == 'reconfigure':
            payload = self._get_reconfig_payload(request, subcloud.name)
            if not payload:
                pecan.abort(400, _('Body required'))

            if subcloud.deploy_status not in [consts.DEPLOY_STATE_DONE,
                                              consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                                              consts.DEPLOY_STATE_DEPLOY_FAILED]:
                pecan.abort(400, _('Subcloud deploy status must be either '
                                   'complete, deploy-prep-failed or deploy-failed'))
            sysadmin_password = \
                payload.get('sysadmin_password')
            if not sysadmin_password:
                pecan.abort(400, _('subcloud sysadmin_password required'))

            try:
                payload['sysadmin_password'] = base64.b64decode(
                    sysadmin_password).decode('utf-8')
            except Exception:
                msg = _('Failed to decode subcloud sysadmin_password, '
                        'verify the password is base64 encoded')
                LOG.exception(msg)
                pecan.abort(400, msg)

            try:
                subcloud = self.rpc_client.reconfigure_subcloud(context, subcloud_id,
                                                                payload)
                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to reconfigure subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to reconfigure subcloud'))
        elif verb == 'update_status':
            res = self.updatestatus(subcloud.name)
            return res

    @utils.synchronized(LOCK_NAME)
    @index.when(method='delete', template='json')
    def delete(self, subcloud_ref):
        """Delete a subcloud.

        :param subcloud_ref: ID or name of subcloud to delete.
        """
        context = restcomm.extract_context_from_environ()
        subcloud = None

        if subcloud_ref.isdigit():
            # Look up subcloud as an ID
            try:
                subcloud = db_api.subcloud_get(context, subcloud_ref)
            except exceptions.SubcloudNotFound:
                pecan.abort(404, _('Subcloud not found'))
        else:
            # Look up subcloud by name
            try:
                subcloud = db_api.subcloud_get_by_name(context,
                                                       subcloud_ref)
            except exceptions.SubcloudNameNotFound:
                pecan.abort(404, _('Subcloud not found'))

        subcloud_id = subcloud.id

        try:
            # Ask dcmanager-manager to delete the subcloud.
            # It will do all the real work...
            return self.rpc_client.delete_subcloud(context, subcloud_id)
        except RemoteError as e:
            pecan.abort(422, e.value)
        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to delete subcloud'))

    def updatestatus(self, subcloud_name):
        """Update subcloud sync status

        :param subcloud_name: name of the subcloud
        :return: json result object for the operation on success
        """

        payload = self._get_updatestatus_payload(request)
        if not payload:
            pecan.abort(400, _('Body required'))

        endpoint = payload.get('endpoint')
        if not endpoint:
            pecan.abort(400, _('endpoint required'))
        allowed_endpoints = [dcorch_consts.ENDPOINT_TYPE_DC_CERT]
        if endpoint not in allowed_endpoints:
            pecan.abort(400, _('updating endpoint %s status is not allowed'
                               % endpoint))

        status = payload.get('status')
        if not status:
            pecan.abort(400, _('status required'))

        allowed_status = [consts.SYNC_STATUS_IN_SYNC,
                          consts.SYNC_STATUS_OUT_OF_SYNC,
                          consts.SYNC_STATUS_UNKNOWN]
        if status not in allowed_status:
            pecan.abort(400, _('status %s in invalid.' % status))

        LOG.info('update %s set %s=%s' % (subcloud_name, endpoint, status))
        context = restcomm.extract_context_from_environ()
        self.rpc_client.update_subcloud_endpoint_status(
            context, subcloud_name, endpoint, status)

        result = {'result': 'OK'}
        return result
