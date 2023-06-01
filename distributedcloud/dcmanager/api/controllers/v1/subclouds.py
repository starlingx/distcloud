# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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
import re
import yaml

import pecan
from pecan import expose
from pecan import request

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack import patching_v1
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions
from dccommon import install_consts

from keystoneauth1 import exceptions as keystone_exceptions

import tsconfig.tsconfig as tsc

from dcmanager.api.controllers import restcomm
from dcmanager.api.policies import subclouds as subclouds_policy
from dcmanager.api import policy
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api

from dcmanager.rpc import client as rpc_client
from fm_api.constants import FM_ALARM_ID_UNSYNCHRONIZED_RESOURCE
from six.moves import range

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

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

BOOTSTRAP_VALUES_ADDRESSES = [
    'bootstrap-address', 'management_start_address', 'management_end_address',
    'management_gateway_address', 'systemcontroller_gateway_address',
    'external_oam_gateway_address', 'external_oam_floating_address',
    'admin_start_address', 'admin_end_address', 'admin_gateway_address'
]

INSTALL_VALUES_ADDRESSES = [
    'bootstrap_address', 'bmc_address', 'nexthop_gateway',
    'network_address'
]

SUBCLOUD_MANDATORY_NETWORK_PARAMS = [
    'management_subnet', 'management_gateway_ip',
    'management_start_ip', 'management_end_ip'
]

ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS = \
    consts.ANSIBLE_CURRENT_VERSION_BASE_PATH + \
    '/roles/bootstrap/validate-config/vars/main.yml'

FRESH_INSTALL_K8S_VERSION = 'fresh_install_k8s_version'
KUBERNETES_VERSION = 'kubernetes_version'


def _get_multipart_field_name(part):
    content = part.headers[b"Content-Disposition"].decode("utf8")
    regex = 'name="([^"]*)"'
    return re.search(regex, content).group(1)


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
    def _get_common_deploy_files(payload, software_version):
        for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
            # Skip the prestage_images option as it is not relevant in this
            # context
            if f == consts.DEPLOY_PRESTAGE:
                continue
            filename = None
            dir_path = os.path.join(dccommon_consts.DEPLOY_DIR, software_version)
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
            self._get_common_deploy_files(payload, payload['software_version'])

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
        payload = dict()
        content_type = request.headers.get("Content-Type")
        multipart_data = decoder.MultipartDecoder(request.body, content_type)

        for part in multipart_data.parts:
            field_name = _get_multipart_field_name(part)
            field_content = part.text

            # only the install_values field is yaml, force should be bool
            if field_name in [INSTALL_VALUES, 'force']:
                field_content = yaml.safe_load(field_content)

            payload[field_name] = field_content

        return payload

    @staticmethod
    def _get_prestage_payload(request):
        fields = ['sysadmin_password', 'force', consts.PRESTAGE_REQUEST_RELEASE]
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
                elif field == consts.PRESTAGE_REQUEST_RELEASE:
                    payload[consts.PRESTAGE_REQUEST_RELEASE] = val
        return payload

    def _upload_config_file(self, file_item, config_file, config_type):
        try:
            with open(config_file, "w") as f:
                f.write(file_item.decode('utf8'))
        except Exception:
            msg = _("Failed to upload %s file" % config_type)
            LOG.exception(msg)
            pecan.abort(400, msg)

    def _get_reconfig_payload(self, request, subcloud_name, software_version):
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
        self._get_common_deploy_files(payload, software_version)
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

    @staticmethod
    def _get_subcloud_db_install_values(subcloud):
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

    def _validate_subcloud_config(self, context, payload, operation=None):
        """Check whether subcloud config is valid."""

        # Validate the name
        if payload.get('name').isdigit():
            pecan.abort(400, _("name must contain alphabetic characters"))

        # If a subcloud group is not passed, use the default
        group_id = payload.get('group_id', consts.DEFAULT_SUBCLOUD_GROUP_ID)

        if payload.get('name') in [dccommon_consts.DEFAULT_REGION_NAME,
                                   dccommon_consts.SYSTEM_CONTROLLER_NAME]:
            pecan.abort(400, _("name cannot be %(bad_name1)s or %(bad_name2)s")
                        % {'bad_name1': dccommon_consts.DEFAULT_REGION_NAME,
                           'bad_name2': dccommon_consts.SYSTEM_CONTROLLER_NAME})

        admin_subnet = payload.get('admin_subnet', None)
        admin_start_ip = payload.get('admin_start_address', None)
        admin_end_ip = payload.get('admin_end_address', None)
        admin_gateway_ip = payload.get('admin_gateway_address', None)

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
                payload.get('management_subnet'),
                minimum_size=MIN_MANAGEMENT_SUBNET_SIZE,
                existing_networks=subcloud_subnets,
                operation=operation)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_subnet invalid: %s") % e)

        # Parse/validate the start/end addresses
        management_start_ip = None
        try:
            management_start_ip = utils.validate_address_str(
                payload.get('management_start_address'), management_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_start_address invalid: %s") % e)

        management_end_ip = None
        try:
            management_end_ip = utils.validate_address_str(
                payload.get('management_end_address'), management_subnet)
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
        management_gateway_ip = None
        if not admin_gateway_ip:
            try:
                management_gateway_ip = utils.validate_address_str(payload.get(
                    'management_gateway_address'), management_subnet)
            except exceptions.ValidateFail as e:
                LOG.exception(e)
                pecan.abort(400, _("management_gateway_address invalid: %s") % e)

        self._validate_admin_network_config(
            admin_subnet,
            admin_start_ip,
            admin_end_ip,
            admin_gateway_ip,
            subcloud_subnets,
            operation
        )

        # Ensure subcloud management gateway is not within the actual subcloud
        # management subnet address pool for consistency with the
        # systemcontroller gateway restriction below. Address collision
        # is not a concern as the address is added to sysinv.
        if admin_start_ip:
            subcloud_mgmt_address_start = IPAddress(admin_start_ip)
        else:
            subcloud_mgmt_address_start = management_start_ip
        if admin_end_ip:
            subcloud_mgmt_address_end = IPAddress(admin_end_ip)
        else:
            subcloud_mgmt_address_end = management_end_ip
        if admin_gateway_ip:
            subcloud_mgmt_gw_ip = IPAddress(admin_gateway_ip)
        else:
            subcloud_mgmt_gw_ip = management_gateway_ip

        if ((subcloud_mgmt_gw_ip >= subcloud_mgmt_address_start) and
                (subcloud_mgmt_gw_ip <= subcloud_mgmt_address_end)):
            pecan.abort(400, _("%(network)s_gateway_address invalid, "
                               "is within management pool: %(start)s - "
                               "%(end)s") %
                        {'network': 'admin' if admin_gateway_ip else 'management',
                         'start': subcloud_mgmt_address_start,
                         'end': subcloud_mgmt_address_end})

        # Ensure systemcontroller gateway is in the management subnet
        # for the systemcontroller region.
        management_address_pool = self._get_network_address_pool()
        systemcontroller_subnet_str = "%s/%d" % (
            management_address_pool.network,
            management_address_pool.prefix)
        systemcontroller_subnet = IPNetwork(systemcontroller_subnet_str)
        try:
            systemcontroller_gw_ip = utils.validate_address_str(
                payload.get('systemcontroller_gateway_address'),
                systemcontroller_subnet
            )
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("systemcontroller_gateway_address invalid: %s") % e)

        # Ensure systemcontroller gateway is not within the actual
        # management subnet address pool to prevent address collision.
        mgmt_address_start = IPAddress(management_address_pool.ranges[0][0])
        mgmt_address_end = IPAddress(management_address_pool.ranges[0][1])
        if ((systemcontroller_gw_ip >= mgmt_address_start) and
                (systemcontroller_gw_ip <= mgmt_address_end)):
            pecan.abort(400, _("systemcontroller_gateway_address invalid, "
                               "is within management pool: %(start)s - "
                               "%(end)s") %
                        {'start': mgmt_address_start, 'end': mgmt_address_end})

        self._validate_oam_network_config(
            payload.get('external_oam_subnet'),
            payload.get('external_oam_gateway_address'),
            payload.get('external_oam_floating_address'),
            subcloud_subnets
        )
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

    def _validate_admin_network_config(self,
                                       admin_subnet_str,
                                       admin_start_address_str,
                                       admin_end_address_str,
                                       admin_gateway_address_str,
                                       existing_networks,
                                       operation):
        """validate whether admin network configuration is valid"""

        if not (admin_subnet_str or admin_start_address_str or
                admin_end_address_str or admin_gateway_address_str):
            return

        MIN_ADMIN_SUBNET_SIZE = 5
        # subtract 3 for network, gateway and broadcast addresses.
        MIN_ADMIN_ADDRESSES = MIN_ADMIN_SUBNET_SIZE - 3

        admin_subnet = None
        try:
            admin_subnet = utils.validate_network_str(
                admin_subnet_str,
                minimum_size=MIN_ADMIN_SUBNET_SIZE,
                existing_networks=existing_networks,
                operation=operation)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("admin_subnet invalid: %s") % e)

        # Parse/validate the start/end addresses
        admin_start_ip = None
        try:
            admin_start_ip = utils.validate_address_str(
                admin_start_address_str, admin_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("admin_start_address invalid: %s") % e)

        admin_end_ip = None
        try:
            admin_end_ip = utils.validate_address_str(
                admin_end_address_str, admin_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("admin_end_address invalid: %s") % e)

        if not admin_start_ip < admin_end_ip:
            pecan.abort(
                400,
                _("admin_start_address  not less than "
                  "admin_end_address"))

        if not len(IPRange(admin_start_ip, admin_end_ip)) >= \
                MIN_ADMIN_ADDRESSES:
            pecan.abort(
                400,
                _("admin address range must contain at least %d "
                  "addresses") % MIN_ADMIN_ADDRESSES)

        # Parse/validate the gateway
        try:
            utils.validate_address_str(
                admin_gateway_address_str, admin_subnet)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("admin_gateway_address invalid: %s") % e)

        subcloud_admin_address_start = IPAddress(admin_start_address_str)
        subcloud_admin_address_end = IPAddress(admin_end_address_str)
        subcloud_admin_gw_ip = IPAddress(admin_gateway_address_str)
        if ((subcloud_admin_gw_ip >= subcloud_admin_address_start) and
                (subcloud_admin_gw_ip <= subcloud_admin_address_end)):
            pecan.abort(400, _("admin_gateway_address invalid, "
                               "is within admin pool: %(start)s - "
                               "%(end)s") %
                        {'start': subcloud_admin_address_start,
                         'end': subcloud_admin_address_end})

    # TODO(nicodemos): Check if subcloud is online and network already exist in the
    # subcloud when the lock/unlock is not required for network reconfiguration
    def _validate_network_reconfiguration(self, payload, subcloud):
        if payload.get('management-state'):
            pecan.abort(422, _("Management state and network reconfiguration must "
                               "be updated separately"))
        if subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED:
            pecan.abort(422, _("A subcloud must be unmanaged to perform network "
                               "reconfiguration"))
        if not payload.get('bootstrap_address'):
            pecan.abort(422, _("The bootstrap_address parameter is required for "
                               "network reconfiguration"))
        # Check if all parameters exist
        if not all(payload.get(value) is not None for value in (
                SUBCLOUD_MANDATORY_NETWORK_PARAMS)):
            mandatory_params = ', '.join('--{}'.format(param.replace(
                '_', '-')) for param in SUBCLOUD_MANDATORY_NETWORK_PARAMS)
            abort_msg = (
                "The following parameters are necessary for "
                "subcloud network reconfiguration: {}".format(mandatory_params)
            )
            pecan.abort(422, _(abort_msg))

        # Check if any network values are already in use
        for param in SUBCLOUD_MANDATORY_NETWORK_PARAMS:
            if payload.get(param) == getattr(subcloud, param):
                pecan.abort(422, _("%s already in use by the subcloud.") % param)

        # Check password and decode it
        sysadmin_password = payload.get('sysadmin_password')
        if not sysadmin_password:
            pecan.abort(400, _('subcloud sysadmin_password required'))
        try:
            payload['sysadmin_password'] = utils.decode_and_normalize_passwd(
                sysadmin_password)
        except Exception:
            msg = _('Failed to decode subcloud sysadmin_password, '
                    'verify the password is base64 encoded')
            LOG.exception(msg)
            pecan.abort(400, msg)

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
           the image is set to the available active/inactive load image.

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

        software_version = payload.get('software_version')
        if not software_version and subcloud:
            software_version = subcloud.software_version
        if 'software_version' in install_values:
            install_software_version = str(install_values.get('software_version'))
            if software_version and software_version != install_software_version:
                pecan.abort(400,
                            _("The software_version value %s in the install values "
                              "yaml file does not match with the specified/current "
                              "software version of %s. Please correct or remove "
                              "this parameter from the yaml file and try again.") %
                            (install_software_version, software_version))
        else:
            # Only install_values payload will be passed to the subcloud
            # installation backend methods. The software_version is required by
            # the installation, so it cannot be absent in the install_values.
            LOG.debug("software_version (%s) is added to install_values" %
                      software_version)
            payload['install_values'].update({'software_version': software_version})
        if 'persistent_size' in install_values:
            persistent_size = install_values.get('persistent_size')
            if not isinstance(persistent_size, int):
                pecan.abort(400, _("The install value persistent_size (in MB) must "
                                   "be a whole number greater than or equal to %s") %
                            consts.DEFAULT_PERSISTENT_SIZE)
            if persistent_size < consts.DEFAULT_PERSISTENT_SIZE:
                # the expected value is less than the default. so throw an error.
                pecan.abort(400, _("persistent_size of %s MB is less than "
                                   "the permitted minimum %s MB ") %
                            (str(persistent_size), consts.DEFAULT_PERSISTENT_SIZE))
        if 'hw_settle' in install_values:
            hw_settle = install_values.get('hw_settle')
            if not isinstance(hw_settle, int):
                pecan.abort(400, _("The install value hw_settle (in seconds) must "
                                   "be a whole number greater than or equal to 0"))
            if hw_settle < 0:
                pecan.abort(400, _("hw_settle of %s seconds is less than 0") %
                            (str(hw_settle)))

        for k in install_consts.MANDATORY_INSTALL_VALUES:
            if k not in install_values:
                if original_install_values:
                    pecan.abort(400, _("Mandatory install value %s not present, "
                                       "existing %s in DB: %s") %
                                (k, k, original_install_values.get(k)))
                else:
                    pecan.abort(400,
                                _("Mandatory install value %s not present") % k)

        # check for the image at load vault load location
        matching_iso, err_msg = utils.get_matching_iso(software_version)
        if err_msg:
            LOG.exception(err_msg)
            pecan.abort(400, _(err_msg))
        LOG.info("Image in install_values is set to %s" % matching_iso)
        payload['install_values'].update({'image': matching_iso})

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
    def _validate_k8s_version(payload):
        """Validate k8s version.

           If the specified release in the payload is not the active release,
           the kubernetes_version value if specified in the subcloud bootstrap
           yaml file must be of the same value as fresh_install_k8s_version of
           the specified release.
        """
        if payload['software_version'] == tsc.SW_VERSION:
            return

        kubernetes_version = payload.get(KUBERNETES_VERSION)
        if kubernetes_version:
            try:
                bootstrap_var_file = utils.get_playbook_for_software_version(
                    ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS,
                    payload['software_version'])
                fresh_install_k8s_version = utils.get_value_from_yaml_file(
                    bootstrap_var_file,
                    FRESH_INSTALL_K8S_VERSION)
                if not fresh_install_k8s_version:
                    pecan.abort(400, _("%s not found in %s")
                                % (FRESH_INSTALL_K8S_VERSION,
                                   bootstrap_var_file))
                if kubernetes_version != fresh_install_k8s_version:
                    pecan.abort(400, _("The kubernetes_version value (%s) "
                                       "specified in the subcloud bootstrap "
                                       "yaml file doesn't match "
                                       "fresh_install_k8s_version value (%s) "
                                       "of the specified release %s")
                                % (kubernetes_version,
                                   fresh_install_k8s_version,
                                   payload['software_version']))
            except exceptions.PlaybookNotFound:
                pecan.abort(400, _("The bootstrap playbook validate-config vars "
                                   "not found for %s software version")
                            % payload['software_version'])

    def _validate_install_parameters(self, payload):
        name = payload.get('name')
        if not name:
            pecan.abort(400, _('name required'))

        system_mode = payload.get('system_mode')
        if not system_mode:
            pecan.abort(400, _('system_mode required'))

        # The admin network is optional, but takes precedence over the
        # management network for communication between the subcloud and
        # system controller if it is defined.
        admin_subnet = payload.get('admin_subnet', None)
        admin_start_ip = payload.get('admin_start_address', None)
        admin_end_ip = payload.get('admin_end_address', None)
        admin_gateway_ip = payload.get('admin_gateway_address', None)
        if any([admin_subnet, admin_start_ip, admin_end_ip,
                admin_gateway_ip]):
            # If any admin parameter is defined, all admin parameters
            # should be defined.
            if not admin_subnet:
                pecan.abort(400, _('admin_subnet required'))
            if not admin_start_ip:
                pecan.abort(400, _('admin_start_address required'))
            if not admin_end_ip:
                pecan.abort(400, _('admin_end_address required'))
            if not admin_gateway_ip:
                pecan.abort(400, _('admin_gateway_address required'))

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
        if (admin_gateway_ip and management_gateway_ip):
            pecan.abort(400, _('admin_gateway_address and '
                               'management_gateway_address cannot be '
                               'specified at the same time'))
        elif (not admin_gateway_ip and not management_gateway_ip):
            pecan.abort(400, _('management_gateway_address required'))

        systemcontroller_gateway_ip = payload.get(
            'systemcontroller_gateway_address')
        if not systemcontroller_gateway_ip:
            pecan.abort(400,
                        _('systemcontroller_gateway_address required'))

        external_oam_subnet = payload.get('external_oam_subnet')
        if not external_oam_subnet:
            pecan.abort(400, _('external_oam_subnet required'))

        external_oam_gateway_ip = payload.get('external_oam_gateway_address')
        if not external_oam_gateway_ip:
            pecan.abort(400, _('external_oam_gateway_address required'))

        external_oam_floating_ip = payload.get('external_oam_floating_address')
        if not external_oam_floating_ip:
            pecan.abort(400, _('external_oam_floating_address required'))

        sysadmin_password = payload.get('sysadmin_password')
        if not sysadmin_password:
            pecan.abort(400, _('subcloud sysadmin_password required'))
        try:
            payload['sysadmin_password'] = utils.decode_and_normalize_passwd(
                sysadmin_password)
        except Exception:
            msg = _('Failed to decode subcloud sysadmin_password, '
                    'verify the password is base64 encoded')
            LOG.exception(msg)
            pecan.abort(400, msg)

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

    def _validate_system_controller_patch_status(self):
        ks_client = self.get_ks_client()
        patching_client = PatchingClient(
            dccommon_consts.DEFAULT_REGION_NAME,
            ks_client.session,
            endpoint=ks_client.endpoint_cache.get_endpoint('patching'))
        patches = patching_client.query()
        patch_ids = list(patches.keys())
        for patch_id in patch_ids:
            valid_states = [
                patching_v1.PATCH_STATE_PARTIAL_APPLY,
                patching_v1.PATCH_STATE_PARTIAL_REMOVE
            ]
            if patches[patch_id]['patchstate'] in valid_states:
                pecan.abort(422, _('Subcloud add is not allowed while system '
                                   'controller patching is still in progress.'))

    def _get_network_address_pool(
            self, network='management',
            region_name=dccommon_consts.DEFAULT_REGION_NAME):
        """Get the region network address pool"""
        ks_client = self.get_ks_client(region_name)
        endpoint = ks_client.endpoint_cache.get_endpoint('sysinv')
        sysinv_client = SysinvClient(region_name,
                                     ks_client.session,
                                     endpoint=endpoint)
        if network == 'admin':
            return sysinv_client.get_admin_address_pool()
        return sysinv_client.get_management_address_pool()

    # TODO(gsilvatr): refactor to use implementation from common/utils and test
    def _get_oam_addresses(self, context, subcloud_name, sc_ks_client):
        """Get the subclouds oam addresses"""

        # First need to retrieve the Subcloud's Keystone session
        try:
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

    def _get_deploy_config_sync_status(self, context, subcloud_name, keystone_client):
        """Get the deploy configuration insync status of the subcloud """
        detected_alarms = None
        try:
            fm_client = FmClient(subcloud_name, keystone_client.session)
            detected_alarms = fm_client.get_alarms_by_id(
                FM_ALARM_ID_UNSYNCHRONIZED_RESOURCE)
        except Exception as ex:
            LOG.error(str(ex))
            return None

        out_of_date = False
        if detected_alarms:
            # Check if any alarm.entity_instance_id contains any of the values
            # in MONITORED_ALARM_ENTITIES.
            # We want to scope 260.002 alarms to the host entity only.
            out_of_date = any(
                any(entity_id in alarm.entity_instance_id
                    for entity_id in dccommon_consts.MONITORED_ALARM_ENTITIES)
                for alarm in detected_alarms
            )
        sync_status = dccommon_consts.DEPLOY_CONFIG_OUT_OF_DATE if out_of_date \
            else dccommon_consts.DEPLOY_CONFIG_UP_TO_DATE
        return sync_status

    def _add_subcloud_to_database(self, context, payload):
        try:
            db_api.subcloud_get_by_name(context, payload['name'])
        except exceptions.SubcloudNameNotFound:
            pass
        else:
            raise exceptions.BadRequest(
                resource='subcloud',
                msg='Subcloud with that name already exists')

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
            payload.get('software_version'),
            utils.get_management_subnet(payload),
            utils.get_management_gateway_address(payload),
            utils.get_management_start_address(payload),
            utils.get_management_end_address(payload),
            payload['systemcontroller_gateway_address'],
            consts.DEPLOY_STATE_NONE,
            consts.ERROR_DESC_EMPTY,
            False,
            group_id,
            data_install=data_install)
        return subcloud

    @staticmethod
    def _append_static_err_content(subcloud):
        err_dict = consts.ERR_MSG_DICT
        status = subcloud.get('deploy-status')
        err_msg = [subcloud.get('error-description')]
        err_code = \
            re.search(r"err_code\s*=\s*(\S*)", err_msg[0], re.IGNORECASE)
        if err_code and err_code.group(1) in err_dict:
            err_msg.append(err_dict.get(err_code.group(1)))
        if status == consts.DEPLOY_STATE_DEPLOY_FAILED:
            err_msg.append(err_dict.get(consts.DEPLOY_ERROR_MSG))
        elif status == consts.DEPLOY_STATE_BOOTSTRAP_FAILED:
            err_msg.append(err_dict.get(consts.BOOTSTRAP_ERROR_MSG))
        subcloud['error-description'] = '\n'.join(err_msg)
        return None

    @index.when(method='GET', template='json')
    def get(self, subcloud_ref=None, detail=None):
        """Get details about subcloud.

        :param subcloud_ref: ID or name of subcloud
        """
        policy.authorize(subclouds_policy.POLICY_ROOT % "get", {},
                         restcomm.extract_credentials_for_policy())
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

                self._append_static_err_content(subcloud_dict)

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

            self._append_static_err_content(subcloud_dict)

            if detail is not None:
                oam_floating_ip = "unavailable"
                deploy_config_sync_status = "unknown"
                if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE:

                    # Get the keystone client that will be used
                    # for _get_deploy_config_sync_status and _get_oam_addresses
                    sc_ks_client = self.get_ks_client(subcloud.name)
                    oam_addresses = self._get_oam_addresses(context,
                                                            subcloud.name, sc_ks_client)
                    if oam_addresses is not None:
                        oam_floating_ip = oam_addresses.oam_floating_ip

                    deploy_config_state = self._get_deploy_config_sync_status(
                        context, subcloud.name, sc_ks_client)
                    if deploy_config_state is not None:
                        deploy_config_sync_status = deploy_config_state

                extra_details = {"oam_floating_ip": oam_floating_ip,
                                 "deploy_config_sync_status": deploy_config_sync_status}

                subcloud_dict.update(extra_details)
            return subcloud_dict

    @utils.synchronized(LOCK_NAME)
    @index.when(method='POST', template='json')
    def post(self, subcloud_ref=None):
        """Create and deploy a new subcloud.

        :param subcloud_ref: ID of or name subcloud (only used when generating
                             config)
        """

        policy.authorize(subclouds_policy.POLICY_ROOT % "create", {},
                         restcomm.extract_credentials_for_policy())
        context = restcomm.extract_context_from_environ()

        if subcloud_ref is None:

            payload = self._get_request_data(request)
            if not payload:
                pecan.abort(400, _('Body required'))

            self._validate_install_parameters(payload)

            # TODO(yuxing): this is not used, should it be removed?
            migrate_str = payload.get('migrate')
            if migrate_str is not None:
                if migrate_str not in ["true", "false"]:
                    pecan.abort(400, _('The migrate option is invalid, '
                                       'valid options are true and false.'))

                if consts.DEPLOY_CONFIG in request.POST:
                    pecan.abort(400, _('migrate with deploy-config is '
                                       'not allowed'))

            # If a subcloud release is not passed, use the current
            # system controller software_version
            payload['software_version'] = payload.get('release', tsc.SW_VERSION)

            self._validate_system_controller_patch_status()

            self._validate_subcloud_config(context, payload)

            self._validate_install_values(payload)

            self._validate_k8s_version(payload)

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

        policy.authorize(subclouds_policy.POLICY_ROOT % "modify", {},
                         restcomm.extract_credentials_for_policy())
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
            # subcloud update
            payload = self._get_patch_data(request)
            if not payload:
                pecan.abort(400, _('Body required'))

            # Check if exist any network reconfiguration parameters
            reconfigure_network = any(payload.get(value) is not None for value in (
                SUBCLOUD_MANDATORY_NETWORK_PARAMS))

            if reconfigure_network:
                system_controller_mgmt_pool = self._get_network_address_pool()
                # Required parameters
                payload['name'] = subcloud.name
                payload['system_controller_network'] = (
                    system_controller_mgmt_pool.network)
                payload['system_controller_network_prefix'] = (
                    system_controller_mgmt_pool.prefix
                )
                # Validation
                self._validate_network_reconfiguration(payload, subcloud)

            management_state = payload.get('management-state')
            group_id = payload.get('group_id')
            description = payload.get('description')
            location = payload.get('location')

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
            if self._validate_install_values(payload, subcloud):
                payload['data_install'] = json.dumps(payload[INSTALL_VALUES])
            try:
                if reconfigure_network:
                    self.dcmanager_rpc_client.update_subcloud_with_network_reconfig(
                        context, subcloud_id, payload)
                    return db_api.subcloud_db_model_to_dict(subcloud)
                subcloud = self.dcmanager_rpc_client.update_subcloud(
                    context, subcloud_id, management_state=management_state,
                    description=description, location=location,
                    group_id=group_id, data_install=payload.get('data_install'),
                    force=force_flag)
                return subcloud
            except RemoteError as e:
                pecan.abort(422, e.value)
            except Exception as e:
                # additional exceptions.
                LOG.exception(e)
                pecan.abort(500, _('Unable to update subcloud'))
        elif verb == 'reconfigure':
            payload = self._get_reconfig_payload(
                request, subcloud.name, subcloud.software_version)
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
                payload['sysadmin_password'] = \
                    utils.decode_and_normalize_passwd(sysadmin_password)
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

            self._validate_install_parameters(payload)

            if payload.get('name') != subcloud.name:
                pecan.abort(400, _('name is incorrect for the subcloud'))

            self._validate_subcloud_config(context, payload, verb)

            # If a subcloud release is not passed, use the current
            # system controller software_version
            payload['software_version'] = payload.get('release', tsc.SW_VERSION)

            self._validate_k8s_version(payload)

            # If the software version of the subcloud is different from the
            # specified or active load, update the software version in install
            # value and delete the image path in install values, then the subcloud
            # will be reinstalled using the image in dc_vault.
            if install_values.get(
                    'software_version') != payload['software_version']:
                install_values['software_version'] = payload['software_version']
                install_values.pop('image', None)

            # Confirm the specified or active load is still in dc-vault if
            # image not in install values, add the matching image into the
            # install values.
            matching_iso, err_msg = utils.get_matching_iso(
                payload['software_version'])
            if err_msg:
                LOG.exception(err_msg)
                pecan.abort(400, _(err_msg))
            LOG.info("Image in install_values is set to %s" % matching_iso)
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
                # Align the software version of the subcloud with reinstall
                # version. Update description, location and group id if offered,
                # update the deploy status as pre-install.
                subcloud = db_api.subcloud_update(
                    context,
                    subcloud_id,
                    description=payload.get('description', subcloud.description),
                    location=payload.get('location', subcloud.location),
                    software_version=payload['software_version'],
                    management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                    deploy_status=consts.DEPLOY_STATE_PRE_INSTALL,
                    first_identity_sync_complete=False,
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
            pecan.abort(410, _('This API is deprecated. '
                               'Please use /v1.0/subcloud-backup/restore'))
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

            prestage_software_version = payload.get(
                consts.PRESTAGE_REQUEST_RELEASE, tsc.SW_VERSION)

            try:
                self.dcmanager_rpc_client.prestage_subcloud(context, payload)
                # local update to deploy_status - this is just for CLI response:
                subcloud.deploy_status = consts.PRESTAGE_STATE_PACKAGES

                subcloud_dict = db_api.subcloud_db_model_to_dict(subcloud)
                subcloud_dict.update(
                    {consts.PRESTAGE_SOFTWARE_VERSION: prestage_software_version})
                return subcloud_dict
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
        policy.authorize(subclouds_policy.POLICY_ROOT % "delete", {},
                         restcomm.extract_credentials_for_policy())
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
