# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2018-2022 Wind River Systems, Inc.
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
# Copyright (c) 2017-2022 Wind River Systems, Inc.
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

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions
from dccommon import install_consts

from keystoneauth1 import exceptions as keystone_exceptions

import tsconfig.tsconfig as tsc

from dcmanager.api.controllers import restcomm
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api

from dcmanager.rpc import client as rpc_client
from six.moves import range

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

LOCK_NAME = 'SubcloudsController'

BOOTSTRAP_VALUES = 'bootstrap_values'
INSTALL_VALUES = 'install_values'
RESTORE_VALUES = 'restore_values'

SUBCLOUD_ADD_MANDATORY_FILE = [
    BOOTSTRAP_VALUES,
]

SUBCLOUD_RECONFIG_MANDATORY_FILE = [
    consts.DEPLOY_CONFIG,
]

SUBCLOUD_RESTORE_MANDATORY_FILE = [
    RESTORE_VALUES,
]

SUBCLOUD_ADD_GET_FILE_CONTENTS = [
    BOOTSTRAP_VALUES,
    INSTALL_VALUES,
]

BOOTSTRAP_VALUES_ADDRESSES = [
    'bootstrap-address', 'management_start_address', 'management_end_address',
    'management_gateway_address', 'systemcontroller_gateway_address',
    'external_oam_gateway_address', 'external_oam_floating_address'
]

INSTALL_VALUES_ADDRESSES = [
    'bootstrap_address', 'bmc_address', 'nexthop_gateway',
    'network_address'
]

# The following parameters can be provided by the user for
# remote subcloud restore
#   - initial_backup_dir (default to /opt/platform-backup)
#   - backup_filename (mandatory parameter)
#   - ansible_ssh_pass (sysadmin_password)
#   - ansible_become_pass (sysadmin_password)
#   - on_box_data (default to true)
#   - wipe_ceph_osds (default to false)
#   - ansible_remote_tmp (default to /tmp)
MANDATORY_RESTORE_VALUES = [
    'backup_filename',
]


class SubcloudsController(object):
    VERSION_ALIASES = {
        'Newton': '1.0',
    }

    def __init__(self):
        super(SubcloudsController, self).__init__()
        self.dcmanager_rpc_client = rpc_client.ManagerClient()
        self.dcmanager_state_rpc_client = rpc_client.SubcloudStateClient()

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
            # Skip the prestage_images option as it is not relevant in this
            # context
            if f == consts.DEPLOY_PRESTAGE:
                continue
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
            fn = self._get_config_file_path(payload['name'], consts.DEPLOY_CONFIG)
            self._upload_config_file(contents, fn, consts.DEPLOY_CONFIG)
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
                for hk, hv in part.headers.items():
                    if (hk.decode('utf8') == 'Content-Disposition' and
                            f in hv.decode('utf8')):
                        data = yaml.safe_load(part.content.decode('utf8'))
                        payload.update({f: data})
        return payload

    @staticmethod
    def _get_prestage_payload(request):
        fields = ['sysadmin_password', 'force']
        payload = {
            'force': False
        }
        try:
            body = json.loads(request.body)
        except Exception:
            pecan.abort(400, _('Request body is malformed.'))

        for field in fields:
            val = body.get(field)
            if val is None:
                if field == 'sysadmin_password':
                    pecan.abort(400, _("%s is required." % field))
            else:
                if field == 'sysadmin_password':
                    try:
                        base64.b64decode(val).decode('utf-8')
                        payload['sysadmin_password'] = val
                    except Exception:
                        pecan.abort(
                            400,
                            _('Failed to decode subcloud sysadmin_password, '
                              'verify the password is base64 encoded'))
                elif field == 'force':
                    if val.lower() in ('true', 'false', 't', 'f'):
                        payload['force'] = val.lower() in ('true', 't')
                    else:
                        pecan.abort(
                            400, _('Invalid value for force option: %s' % val))
        return payload

    def _upload_config_file(self, file_item, config_file, config_type):
        try:
            with open(config_file, "w") as f:
                f.write(file_item.decode('utf8'))
        except Exception:
            msg = _("Failed to upload %s file" % config_type)
            LOG.exception(msg)
            pecan.abort(400, msg)

    def _get_reconfig_payload(self, request, subcloud_name):
        payload = dict()
        multipart_data = decoder.MultipartDecoder(
            request.body, pecan.request.headers.get('Content-Type'))

        for filename in SUBCLOUD_RECONFIG_MANDATORY_FILE:
            for part in multipart_data.parts:
                for hk, hv in part.headers.items():
                    hv = hv.decode('utf8')
                    if hk.decode('utf8') == 'Content-Disposition':
                        if filename in hv:
                            fn = self._get_config_file_path(
                                subcloud_name, consts.DEPLOY_CONFIG)
                            self._upload_config_file(
                                part.content, fn, consts.DEPLOY_CONFIG)
                            payload.update({consts.DEPLOY_CONFIG: fn})
                        elif "sysadmin_password" in hv:
                            payload.update({'sysadmin_password': part.content})
        self._get_common_deploy_files(payload)
        return payload

    @staticmethod
    def _get_restore_payload(request):
        payload = dict()
        for f in SUBCLOUD_RESTORE_MANDATORY_FILE:
            if f not in request.POST:
                pecan.abort(400, _("Missing required file for %s") % f)

        multipart_data = decoder.MultipartDecoder(
            request.body, pecan.request.headers.get('Content-Type'))
        for f in SUBCLOUD_RESTORE_MANDATORY_FILE:
            for part in multipart_data.parts:
                for hk, hv in part.headers.items():
                    hv = hv.decode('utf8')
                    if hk.decode('utf8') == 'Content-Disposition':
                        if f in hv:
                            file_item = request.POST[f]
                            file_item.file.seek(0, os.SEEK_SET)
                            data = yaml.safe_load(
                                file_item.file.read().decode('utf8'))
                            payload.update({RESTORE_VALUES: data})
                        elif "sysadmin_password" in hv:
                            payload.update({'sysadmin_password': part.content})
                        elif "with_install" in hv:
                            payload.update({'with_install': part.content})
        return payload

    def _get_config_file_path(self, subcloud_name, config_file_type=None):
        if config_file_type == consts.DEPLOY_CONFIG:
            file_path = os.path.join(
                consts.ANSIBLE_OVERRIDES_PATH,
                subcloud_name + '_' + config_file_type + '.yml'
            )
        elif config_file_type == INSTALL_VALUES:
            file_path = os.path.join(
                consts.ANSIBLE_OVERRIDES_PATH + '/' + subcloud_name,
                config_file_type + '.yml'
            )
        else:
            file_path = os.path.join(
                consts.ANSIBLE_OVERRIDES_PATH,
                subcloud_name + '.yml'
            )
        return file_path

    def _get_subcloud_db_install_values(self, subcloud):
        if not subcloud.data_install:
            msg = _("Failed to read data install from db")
            LOG.exception(msg)
            pecan.abort(400, msg)

        install_values = json.loads(subcloud.data_install)

        # mandatory bootstrap parameters
        mandatory_bootstrap_parameters = [
            'bootstrap_interface',
            'bootstrap_address',
            'bootstrap_address_prefix',
            'bmc_username',
            'bmc_address',
            'bmc_password',
        ]
        for p in mandatory_bootstrap_parameters:
            if p not in install_values:
                msg = _("Failed to get %s from data_install" % p)
                LOG.exception(msg)
                pecan.abort(400, msg)

        install_values.update({
            'ansible_become_pass': consts.TEMP_SYSADMIN_PASSWORD,
            'ansible_ssh_pass': consts.TEMP_SYSADMIN_PASSWORD
        })

        return install_values

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

        if name in [dccommon_consts.DEFAULT_REGION_NAME,
                    dccommon_consts.SYSTEM_CONTROLLER_NAME]:
            pecan.abort(400, _("name cannot be %(bad_name1)s or %(bad_name2)s")
                        % {'bad_name1': dccommon_consts.DEFAULT_REGION_NAME,
                           'bad_name2': dccommon_consts.SYSTEM_CONTROLLER_NAME})

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

        self._validate_oam_network_config(external_oam_subnet_str,
                                          external_oam_gateway_address_str,
                                          external_oam_floating_address_str,
                                          subcloud_subnets)
        self._validate_group_id(context, group_id)

    def _validate_oam_network_config(self,
                                     external_oam_subnet_str,
                                     external_oam_gateway_address_str,
                                     external_oam_floating_address_str,
                                     existing_networks):
        """validate whether oam network configuration is valid"""

        # Parse/validate the oam subnet
        MIN_OAM_SUBNET_SIZE = 3
        oam_subnet = None
        try:
            oam_subnet = utils.validate_network_str(
                external_oam_subnet_str,
                minimum_size=MIN_OAM_SUBNET_SIZE,
                existing_networks=existing_networks)
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

    def _format_ip_address(self, payload):
        """Format IP addresses in 'bootstrap_values' and 'install_values'.

           The IPv6 addresses can be represented in multiple ways. Format and
           update the IP addresses in payload before saving it to database.
        """
        if INSTALL_VALUES in payload:
            for k in INSTALL_VALUES_ADDRESSES:
                if k in payload[INSTALL_VALUES]:
                    try:
                        address = IPAddress(payload[INSTALL_VALUES].get(k)).format()
                    except AddrFormatError as e:
                        LOG.exception(e)
                        pecan.abort(400, _("%s invalid: %s") % (k, e))
                    payload[INSTALL_VALUES].update({k: address})

        for k in BOOTSTRAP_VALUES_ADDRESSES:
            if k in payload:
                try:
                    address = IPAddress(payload.get(k)).format()
                except AddrFormatError as e:
                    LOG.exception(e)
                    pecan.abort(400, _("%s invalid: %s") % (k, e))
                payload.update({k: address})

    @staticmethod
    def _validate_install_values(payload, subcloud=None):
        """Validate install values if 'install_values' is present in payload.

           The image in payload install values is optional, and if not provided,
           the image is set to the available active load image.

           :return boolean: True if bmc install requested, otherwise False
        """
        install_values = payload.get('install_values')
        if not install_values:
            return False

        original_install_values = None
        if subcloud:
            if subcloud.data_install:
                original_install_values = json.loads(subcloud.data_install)

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

        if 'software_version' in install_values:
            software_version = str(install_values.get('software_version'))
        else:
            if original_install_values:
                pecan.abort(400, _("Mandatory install value software_version not present, "
                                   "existing software_version in DB: %s") %
                            original_install_values.get("software_version"))
            else:
                pecan.abort(400, _("Mandatory install value software_version not present"))
        if 'persistent_size' in install_values:
            persistent_size = install_values.get('persistent_size')
            if not isinstance(persistent_size, int):
                pecan.abort(400, _("The install value persistent_size (in MB) must be a"
                                   " whole number greater than or equal to %s") %
                            consts.DEFAULT_PERSISTENT_SIZE)
            if persistent_size < consts.DEFAULT_PERSISTENT_SIZE:
                # the expected value is less than the default. so throw an error.
                pecan.abort(400, _("persistent_size of %s MB is less than "
                                   "the permitted minimum %s MB ") %
                            (str(persistent_size), consts.DEFAULT_PERSISTENT_SIZE))

        for k in install_consts.MANDATORY_INSTALL_VALUES:
            if k not in install_values:
                if k == 'image':
                    if software_version == tsc.SW_VERSION:
                        # check for the image at load vault load location
                        matching_iso, matching_sig = \
                            SubcloudsController.verify_active_load_in_vault()
                        LOG.info("image was not in install_values: will reference %s" %
                                 matching_iso)
                    else:
                        pecan.abort(400, _("Image was not in install_values, and "
                                           "software version %s in install values "
                                           "did not match the active load %s") %
                                    (software_version, tsc.SW_VERSION))
                else:
                    if original_install_values:
                        pecan.abort(400, _("Mandatory install value %s not present, "
                                           "existing %s in DB: %s") %
                                    (k, k, original_install_values.get(k)))
                    else:
                        pecan.abort(400, _("Mandatory install value %s not present") % k)

        if (install_values['install_type'] not in
                list(range(install_consts.SUPPORTED_INSTALL_TYPES))):
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

        if 'rd.net.timeout.ipv6dad' in install_values:
            try:
                ipv6dad_timeout = int(install_values['rd.net.timeout.ipv6dad'])
                if ipv6dad_timeout <= 0:
                    pecan.abort(400, _("rd.net.timeout.ipv6dad must be greater "
                                       "than 0: %d") % ipv6dad_timeout)
            except ValueError as e:
                LOG.exception(e)
                pecan.abort(400, _("rd.net.timeout.ipv6dad invalid: %s") % e)

        return True

    @staticmethod
    def _validate_restore_values(payload):
        """Validate the restore values to ensure parameters for remote restore are present"""

        restore_values = payload.get(RESTORE_VALUES)
        for p in MANDATORY_RESTORE_VALUES:
            if p not in restore_values:
                pecan.abort(400, _('Mandatory restore value %s not present') % p)

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

    @staticmethod
    def get_ks_client(region_name=dccommon_consts.DEFAULT_REGION_NAME):
        """This will get a new keystone client (and new token)"""
        try:
            os_client = OpenStackDriver(region_name=region_name,
                                        region_clients=None)
            return os_client.keystone_client
        except Exception:
            LOG.warn('Failure initializing KeystoneClient '
                     'for region %s' % region_name)
            raise

    def _get_management_address_pool(self, context):
        """Get the system controller's management address pool"""
        ks_client = self.get_ks_client()
        endpoint = ks_client.endpoint_cache.get_endpoint('sysinv')
        sysinv_client = SysinvClient(dccommon_consts.DEFAULT_REGION_NAME,
                                     ks_client.session,
                                     endpoint=endpoint)
        return sysinv_client.get_management_address_pool()

    def _get_oam_addresses(self, context, subcloud_name):
        """Get the subclouds oam addresses"""

        # First need to retrieve the Subcloud's Keystone session
        try:
            sc_ks_client = self.get_ks_client(subcloud_name)
            endpoint = sc_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(subcloud_name,
                                         sc_ks_client.session,
                                         endpoint=endpoint)
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
            software_version = payload['install_values']['software_version']
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

    @staticmethod
    def verify_active_load_in_vault():
        try:
            matching_iso, matching_sig = utils.get_vault_load_files(tsc.SW_VERSION)
            if not matching_iso:
                msg = _('Failed to get active load image. Provide '
                        'active load image via '
                        '"system --os-region-name SystemController '
                        'load-import --active"')
                LOG.exception(msg)
                pecan.abort(400, msg)
            return matching_iso, matching_sig
        except Exception as e:
            LOG.exception(str(e))
            pecan.abort(400, str(e))

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
                                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

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
                oam_floating_ip = "unavailable"
                if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                    oam_addresses = self._get_oam_addresses(context,
                                                            subcloud.name)
                    if oam_addresses is not None:
                        oam_floating_ip = oam_addresses.oam_floating_ip

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

            # TODO(yuxing): this is not used, should it be removed?
            migrate_str = payload.get('migrate')
            if migrate_str is not None:
                if migrate_str not in ["true", "false"]:
                    pecan.abort(400, _('The migrate option is invalid, '
                                       'valid options are true and false.'))

                if consts.DEPLOY_CONFIG in request.POST:
                    pecan.abort(400, _('migrate with deploy-config is '
                                       'not allowed'))

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

            self._validate_install_values(payload)

            self._format_ip_address(payload)

            # Upload the deploy config files if it is included in the request
            # It has a dependency on the subcloud name, and it is called after
            # the name has been validated
            self._upload_deploy_config_file(request, payload)

            try:
                # Add the subcloud details to the database
                subcloud = self._add_subcloud_to_database(context, payload)
                # Ask dcmanager-manager to add the subcloud.
                # It will do all the real work...
                self.dcmanager_rpc_client.add_subcloud(context, payload)
                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception(
                    "Unable to create subcloud %s" % payload.get('name'))
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
                    management_state not in [dccommon_consts.MANAGEMENT_UNMANAGED,
                                             dccommon_consts.MANAGEMENT_MANAGED]:
                pecan.abort(400, _('Invalid management-state'))

            force_flag = payload.get('force')
            if force_flag is not None:
                if force_flag not in [True, False]:
                    pecan.abort(400, _('Invalid force value'))
                elif management_state != dccommon_consts.MANAGEMENT_MANAGED:
                    pecan.abort(400, _('Invalid option: force'))

            # Verify the group_id is valid
            if group_id is not None:
                try:
                    # group_id may be passed in the payload as an int or str
                    group_id = str(group_id)
                    if group_id.isdigit():
                        grp = db_api.subcloud_group_get(context, group_id)
                    else:
                        # replace the group_id (name) with the id
                        grp = db_api.subcloud_group_get_by_name(context,
                                                                group_id)
                    group_id = grp.id
                except exceptions.SubcloudGroupNameNotFound:
                    pecan.abort(400, _('Invalid group'))
                except exceptions.SubcloudGroupNotFound:
                    pecan.abort(400, _('Invalid group'))

            data_install = None
            if self._validate_install_values(payload, subcloud):
                data_install = json.dumps(payload[INSTALL_VALUES])

            try:
                # Inform dcmanager that subcloud has been updated.
                # It will do all the real work...
                subcloud = self.dcmanager_rpc_client.update_subcloud(
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

            if (subcloud.deploy_status
                    not in [consts.DEPLOY_STATE_DONE,
                            consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                            consts.DEPLOY_STATE_DEPLOY_FAILED]
                    and not prestage.is_deploy_status_prestage(
                        subcloud.deploy_status)):
                pecan.abort(400,
                            _('Subcloud deploy status must be either '
                              'complete, deploy-prep-failed, deploy-failed, '
                              'or prestage-...'))
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
                subcloud = self.dcmanager_rpc_client.reconfigure_subcloud(
                    context, subcloud_id, payload)
                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to reconfigure subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to reconfigure subcloud'))
        elif verb == "reinstall":
            payload = self._get_request_data(request)
            install_values = self._get_subcloud_db_install_values(subcloud)

            if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                msg = _('Cannot re-install an online subcloud')
                LOG.exception(msg)
                pecan.abort(400, msg)

            # Validate the bootstrap values with the data in central cloud.
            # Stop the process if the boostrap value is not equal to the data
            # in DB. Re-use the data from DB if it is not passed.
            name = payload.get('name', subcloud.name)
            if name != subcloud.name:
                pecan.abort(400, _('name is incorrect for the subcloud'))
            else:
                payload['name'] = name

            system_mode = payload.get('system_mode')
            if not system_mode:
                pecan.abort(400, _('system_mode required'))

            management_subnet = payload.get('management_subnet',
                                            subcloud.management_subnet)
            if management_subnet != subcloud.management_subnet:
                pecan.abort(400, _('management_subnet is incorrect  for subcloud'))
            else:
                payload['management_subnet'] = management_subnet

            management_start_ip = payload.get('management_start_address',
                                              subcloud.management_start_ip)
            if management_start_ip != subcloud.management_start_ip:
                pecan.abort(400, _('management_start_address is incorrect for '
                                   'the subcloud'))
            else:
                payload['management_start_address'] = management_start_ip

            management_end_ip = payload.get('management_end_address',
                                            subcloud.management_end_ip)
            if management_end_ip != subcloud.management_end_ip:
                pecan.abort(400, _('management_end_address is incorrect for '
                                   'the subcloud'))
            else:
                payload['management_end_address'] = management_end_ip

            management_gateway_ip = payload.get('management_gateway_address',
                                                subcloud.management_gateway_ip)
            if management_gateway_ip != subcloud.management_gateway_ip:
                pecan.abort(400, _('management_gateway_address is incorrect for '
                                   'the subcloud'))
            else:
                payload['management_gateway_address'] = management_gateway_ip

            systemcontroller_gateway_ip = \
                payload.get('systemcontroller_gateway_address',
                            subcloud.systemcontroller_gateway_ip)
            if systemcontroller_gateway_ip != subcloud.systemcontroller_gateway_ip:
                pecan.abort(400, _('systemcontroller_gateway_address is incorrect '
                                   'for the subcloud'))
            else:
                payload['systemcontroller_gateway_address'] = \
                    systemcontroller_gateway_ip

            external_oam_subnet = payload.get('external_oam_subnet')
            if not external_oam_subnet:
                pecan.abort(400, _('external_oam_subnet required'))

            external_oam_gateway_ip = payload.get('external_oam_gateway_address')
            if not external_oam_gateway_ip:
                pecan.abort(400, _('external_oam_gateway_address required'))

            external_oam_floating_ip = \
                payload.get('external_oam_floating_address')
            if not external_oam_floating_ip:
                pecan.abort(400, _('external_oam_floating_address required'))

            sysadmin_password = payload.get('sysadmin_password')
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

            # Search existing subcloud subnets in db
            subcloud_subnets = []
            subclouds = db_api.subcloud_get_all(context)
            for k in subclouds:
                subcloud_subnets.append(IPNetwork(k.management_subnet))

            self._validate_oam_network_config(external_oam_subnet,
                                              external_oam_gateway_ip,
                                              external_oam_floating_ip,
                                              subcloud_subnets)

            # If the software version of the subcloud is different from the
            # central cloud, update the software version in install valuse and
            # delete the image path in install values, then the subcloud will
            # be reinstalled using the image in dc_vault.
            if install_values.get('software_version') != tsc.SW_VERSION:
                install_values['software_version'] = tsc.SW_VERSION
                install_values.pop('image', None)

            # Confirm the active system controller load is still in dc-vault if
            # image not in install values, add the matching image into the
            # install values.
            if 'image' not in install_values:
                matching_iso, matching_sig = \
                    SubcloudsController.verify_active_load_in_vault()
                LOG.info("image was not in install_values: will reference %s" %
                         matching_iso)
                install_values['image'] = matching_iso

            # Update the install values in payload
            payload.update({
                'bmc_password': install_values.get('bmc_password'),
                'install_values': install_values,
            })

            # Update data install(software version, image path)
            data_install = None
            if 'install_values' in payload:
                data_install = json.dumps(payload['install_values'])

            # Upload the deploy config files if it is included in the request
            self._upload_deploy_config_file(request, payload)

            try:
                # Align the software version of the subcloud with the central
                # cloud. Update description, location and group id if offered,
                # update the deploy status as pre-install.
                db_api.subcloud_update(
                    context,
                    subcloud_id,
                    description=payload.get('description', subcloud.description),
                    location=payload.get('location', subcloud.location),
                    software_version=tsc.SW_VERSION,
                    management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                    deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                    data_install=data_install)

                self.dcmanager_rpc_client.reinstall_subcloud(
                    context, subcloud_id, payload)

                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to reinstall subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to reinstall subcloud'))
        elif verb == "restore":
            payload = self._get_restore_payload(request)
            if not payload:
                pecan.abort(400, _('Body required'))

            if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
                pecan.abort(400, _('Subcloud can not be restored while it is still '
                                   'in managed state. Please unmanage the subcloud '
                                   'and try again.'))
            elif subcloud.deploy_status in [consts.DEPLOY_STATE_INSTALLING,
                                            consts.DEPLOY_STATE_BOOTSTRAPPING,
                                            consts.DEPLOY_STATE_DEPLOYING]:
                pecan.abort(400, _('This operation is not allowed while subcloud install, '
                                   'bootstrap or deploy is in progress.'))
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

            with_install = payload.get('with_install')

            if with_install is not None:
                if with_install == 'true' or with_install == 'True':
                    payload.update({'with_install': True})
                elif with_install == 'false' or with_install == 'False':
                    payload.update({'with_install': False})
                else:
                    pecan.abort(400, _('Invalid with_install value'))

            self._validate_restore_values(payload)

            if with_install:
                # Request to remote install as part of subcloud restore. Confirm the
                # subcloud install data in the db still contain the required parameters
                # for remote install.
                install_values = self._get_subcloud_db_install_values(subcloud)
                payload.update({
                    'install_values': install_values,
                })

                # Confirm the active system controller load is still in dc-vault
                SubcloudsController.verify_active_load_in_vault()
            else:
                # Not Redfish capable subcloud. The subcloud has been reinstalled
                # and required patches have been applied.
                #
                # Pseudo code:
                #   - Retrieve install_values of the subcloud from the database.
                #     If it does not exist, try to retrieve the bootstrap address
                #     from its ansible inventory file (/var/opt/dc/ansible).
                #   - If the bootstrap address can be obtained, add install_values
                #     to the payload and continue.
                #   - If the bootstrap address cannot be obtained, abort with an
                #     error message advising the user to run "dcmanager subcloud
                #     update --bootstrap-address <bootstrap_address>" command
                msg = _('This operation is not yet supported for subclouds without '
                        'remote install capability.')
                LOG.exception(msg)
                pecan.abort(400, msg)

            try:
                self.dcmanager_rpc_client.restore_subcloud(context,
                                                           subcloud_id,
                                                           payload)
                # Return deploy_status as pre-restore
                subcloud.deploy_status = consts.DEPLOY_STATE_PRE_RESTORE
                return db_api.subcloud_db_model_to_dict(subcloud)
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to restore subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to restore subcloud'))
        elif verb == 'update_status':
            res = self.updatestatus(subcloud.name)
            return res
        elif verb == 'prestage':
            payload = self._get_prestage_payload(request)
            payload['subcloud_name'] = subcloud.name
            try:
                prestage.global_prestage_validate(payload)
            except exceptions.PrestagePreCheckFailedException as exc:
                LOG.exception("global_prestage_validate failed")
                pecan.abort(400, _(str(exc)))

            try:
                payload['oam_floating_ip'] = \
                    prestage.validate_prestage(subcloud, payload)
            except exceptions.PrestagePreCheckFailedException as exc:
                LOG.exception("validate_prestage failed")
                pecan.abort(400, _(str(exc)))

            try:
                self.dcmanager_rpc_client.prestage_subcloud(context, payload)
                # local update to deploy_status - this is just for CLI response:
                subcloud.deploy_status = consts.PRESTAGE_STATE_PREPARE
                return db_api.subcloud_db_model_to_dict(subcloud)

            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception:
                LOG.exception("Unable to prestage subcloud %s" % subcloud.name)
                pecan.abort(500, _('Unable to prestage subcloud'))

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
            return self.dcmanager_rpc_client.delete_subcloud(context,
                                                             subcloud_id)
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
        allowed_endpoints = [dccommon_consts.ENDPOINT_TYPE_DC_CERT]
        if endpoint not in allowed_endpoints:
            pecan.abort(400, _('updating endpoint %s status is not allowed'
                               % endpoint))

        status = payload.get('status')
        if not status:
            pecan.abort(400, _('status required'))

        allowed_status = [dccommon_consts.SYNC_STATUS_IN_SYNC,
                          dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                          dccommon_consts.SYNC_STATUS_UNKNOWN]
        if status not in allowed_status:
            pecan.abort(400, _('status %s in invalid.' % status))

        LOG.info('update %s set %s=%s' % (subcloud_name, endpoint, status))
        context = restcomm.extract_context_from_environ()
        self.dcmanager_state_rpc_client.update_subcloud_endpoint_status(
            context, subcloud_name, endpoint, status)

        result = {'result': 'OK'}
        return result
