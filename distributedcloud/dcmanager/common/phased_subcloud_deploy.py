#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import json
import os
import typing

import netaddr
from oslo_log import log as logging
import pecan
import tsconfig.tsconfig as tsc
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import patching_v1
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import install_consts
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models

LOG = logging.getLogger(__name__)

ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS = \
    consts.ANSIBLE_CURRENT_VERSION_BASE_PATH + \
    '/roles/bootstrap/validate-config/vars/main.yml'

FRESH_INSTALL_K8S_VERSION = 'fresh_install_k8s_version'
KUBERNETES_VERSION = 'kubernetes_version'

INSTALL_VALUES = 'install_values'
INSTALL_VALUES_ADDRESSES = [
    'bootstrap_address', 'bmc_address', 'nexthop_gateway',
    'network_address'
]

BOOTSTRAP_VALUES_ADDRESSES = [
    'bootstrap-address', 'management_start_address', 'management_end_address',
    'management_gateway_address', 'systemcontroller_gateway_address',
    'external_oam_gateway_address', 'external_oam_floating_address',
    'admin_start_address', 'admin_end_address', 'admin_gateway_address'
]


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


def validate_bootstrap_values(payload: dict):
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


def validate_system_controller_patch_status(operation: str):
    ks_client = get_ks_client()
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
            pecan.abort(422,
                        _('Subcloud %s is not allowed while system '
                          'controller patching is still in progress.')
                        % operation)


def validate_subcloud_config(context, payload, operation=None,
                             ignore_conflicts_with=None):
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
        # Ignore management subnet conflict with the subcloud specified by
        # ignore_conflicts_with
        if ignore_conflicts_with and (subcloud.id == ignore_conflicts_with.id):
            continue
        subcloud_subnets.append(netaddr.IPNetwork(subcloud.management_subnet))

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

    if not len(netaddr.IPRange(management_start_ip, management_end_ip)) >= \
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

    validate_admin_network_config(
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
        subcloud_mgmt_address_start = netaddr.IPAddress(admin_start_ip)
    else:
        subcloud_mgmt_address_start = management_start_ip
    if admin_end_ip:
        subcloud_mgmt_address_end = netaddr.IPAddress(admin_end_ip)
    else:
        subcloud_mgmt_address_end = management_end_ip
    if admin_gateway_ip:
        subcloud_mgmt_gw_ip = netaddr.IPAddress(admin_gateway_ip)
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
    management_address_pool = get_network_address_pool()
    systemcontroller_subnet_str = "%s/%d" % (
        management_address_pool.network,
        management_address_pool.prefix)
    systemcontroller_subnet = netaddr.IPNetwork(systemcontroller_subnet_str)
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
    mgmt_address_start = netaddr.IPAddress(management_address_pool.ranges[0][0])
    mgmt_address_end = netaddr.IPAddress(management_address_pool.ranges[0][1])
    if ((systemcontroller_gw_ip >= mgmt_address_start) and
            (systemcontroller_gw_ip <= mgmt_address_end)):
        pecan.abort(400, _("systemcontroller_gateway_address invalid, "
                           "is within management pool: %(start)s - "
                           "%(end)s") %
                    {'start': mgmt_address_start, 'end': mgmt_address_end})

    validate_oam_network_config(
        payload.get('external_oam_subnet'),
        payload.get('external_oam_gateway_address'),
        payload.get('external_oam_floating_address'),
        subcloud_subnets
    )
    validate_group_id(context, group_id)


def validate_admin_network_config(admin_subnet_str,
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

    if not len(netaddr.IPRange(admin_start_ip, admin_end_ip)) >= \
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

    subcloud_admin_address_start = netaddr.IPAddress(admin_start_address_str)
    subcloud_admin_address_end = netaddr.IPAddress(admin_end_address_str)
    subcloud_admin_gw_ip = netaddr.IPAddress(admin_gateway_address_str)
    if ((subcloud_admin_gw_ip >= subcloud_admin_address_start) and
            (subcloud_admin_gw_ip <= subcloud_admin_address_end)):
        pecan.abort(400, _("admin_gateway_address invalid, "
                           "is within admin pool: %(start)s - "
                           "%(end)s") %
                    {'start': subcloud_admin_address_start,
                        'end': subcloud_admin_address_end})


def validate_oam_network_config(external_oam_subnet_str,
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


def validate_group_id(context, group_id):
    try:
        # The DB API will raise an exception if the group_id is invalid
        db_api.subcloud_group_get(context, group_id)
    except Exception as e:
        LOG.exception(e)
        pecan.abort(400, _("Invalid group_id"))


def get_network_address_pool(network='management',
                             region_name=dccommon_consts.DEFAULT_REGION_NAME):
    """Get the region network address pool"""
    ks_client = get_ks_client(region_name)
    endpoint = ks_client.endpoint_cache.get_endpoint('sysinv')
    sysinv_client = SysinvClient(region_name,
                                 ks_client.session,
                                 endpoint=endpoint)
    if network == 'admin':
        return sysinv_client.get_admin_address_pool()
    return sysinv_client.get_management_address_pool()


def validate_install_values(payload, subcloud=None):
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
        ip_version = (netaddr.IPAddress(install_values['bootstrap_address']).
                      version)
    except netaddr.AddrFormatError as e:
        LOG.exception(e)
        pecan.abort(400, _("bootstrap_address invalid: %s") % e)

    try:
        bmc_address = netaddr.IPAddress(install_values['bmc_address'])
    except netaddr.AddrFormatError as e:
        LOG.exception(e)
        pecan.abort(400, _("bmc_address invalid: %s") % e)

    if bmc_address.version != ip_version:
        pecan.abort(400, _("bmc_address and bootstrap_address "
                           "must be the same IP version"))

    if 'nexthop_gateway' in install_values:
        try:
            gateway_ip = netaddr.IPAddress(install_values['nexthop_gateway'])
        except netaddr.AddrFormatError as e:
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


def validate_k8s_version(payload):
    """Validate k8s version.

        If the specified release in the payload is not the active release,
        the kubernetes_version value if specified in the subcloud bootstrap
        yaml file must be of the same value as fresh_install_k8s_version of
        the specified release.
    """
    software_version = payload['software_version']
    if software_version == tsc.SW_VERSION:
        return

    kubernetes_version = payload.get(KUBERNETES_VERSION)
    if kubernetes_version:
        try:
            bootstrap_var_file = utils.get_playbook_for_software_version(
                ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS,
                software_version)
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
                               software_version))
        except exceptions.PlaybookNotFound:
            pecan.abort(400, _("The bootstrap playbook validate-config vars "
                               "not found for %s software version")
                        % software_version)


def validate_sysadmin_password(payload: dict):
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


def format_ip_address(payload):
    """Format IP addresses in 'bootstrap_values' and 'install_values'.

        The IPv6 addresses can be represented in multiple ways. Format and
        update the IP addresses in payload before saving it to database.
    """
    if INSTALL_VALUES in payload:
        for k in INSTALL_VALUES_ADDRESSES:
            if k in payload[INSTALL_VALUES]:
                try:
                    address = netaddr.IPAddress(payload[INSTALL_VALUES]
                                                .get(k)).format()
                except netaddr.AddrFormatError as e:
                    LOG.exception(e)
                    pecan.abort(400, _("%s invalid: %s") % (k, e))
                payload[INSTALL_VALUES].update({k: address})

    for k in BOOTSTRAP_VALUES_ADDRESSES:
        if k in payload:
            try:
                address = netaddr.IPAddress(payload.get(k)).format()
            except netaddr.AddrFormatError as e:
                LOG.exception(e)
                pecan.abort(400, _("%s invalid: %s") % (k, e))
            payload.update({k: address})


def upload_deploy_config_file(request, payload):
    if consts.DEPLOY_CONFIG in request.POST:
        file_item = request.POST[consts.DEPLOY_CONFIG]
        filename = getattr(file_item, 'filename', '')
        if not filename:
            pecan.abort(400, _("No %s file uploaded"
                        % consts.DEPLOY_CONFIG))
        file_item.file.seek(0, os.SEEK_SET)
        contents = file_item.file.read()
        # the deploy config needs to upload to the override location
        fn = get_config_file_path(payload['name'], consts.DEPLOY_CONFIG)
        upload_config_file(contents, fn, consts.DEPLOY_CONFIG)
        payload.update({consts.DEPLOY_CONFIG: fn})
        get_common_deploy_files(payload, payload['software_version'])


def get_config_file_path(subcloud_name, config_file_type=None):
    basepath = consts.ANSIBLE_OVERRIDES_PATH
    if config_file_type == consts.DEPLOY_CONFIG:
        filename = f"{subcloud_name}_{config_file_type}.yml"
    elif config_file_type == consts.INSTALL_VALUES:
        basepath = os.path.join(basepath, subcloud_name)
        filename = f'{config_file_type}.yml'
    else:
        filename = f"{subcloud_name}.yml"
    file_path = os.path.join(basepath, filename)
    return file_path


def upload_config_file(file_item, config_file, config_type):
    try:
        with open(config_file, "w") as f:
            f.write(file_item.decode('utf8'))
    except Exception:
        msg = _("Failed to upload %s file" % config_type)
        LOG.exception(msg)
        pecan.abort(400, msg)


def get_common_deploy_files(payload, software_version):
    missing_deploy_files = []
    for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
        # Skip the prestage_images option as it is
        # not relevant in this context
        if f == consts.DEPLOY_PRESTAGE:
            continue
        filename = None
        dir_path = os.path.join(dccommon_consts.DEPLOY_DIR, software_version)
        if os.path.isdir(dir_path):
            filename = utils.get_filename_by_prefix(dir_path, f + '_')
        if not filename:
            missing_deploy_files.append(f)
        else:
            payload.update({f: os.path.join(dir_path, filename)})
    if missing_deploy_files:
        missing_deploy_files_str = ', '.join(missing_deploy_files)
        msg = _("Missing required deploy files: %s" % missing_deploy_files_str)
        pecan.abort(400, msg)


def validate_subcloud_name_availability(context, subcloud_name):
    try:
        db_api.subcloud_get_by_name(context, subcloud_name)
    except exceptions.SubcloudNameNotFound:
        pass
    else:
        msg = _("Subcloud with name=%s already exists") % subcloud_name
        LOG.info(msg)
        pecan.abort(409, msg)


def check_required_parameters(request, required_parameters):
    missing_parameters = []
    for p in required_parameters:
        if p not in request.POST:
            missing_parameters.append(p)

    if missing_parameters:
        parameters_str = ', '.join(missing_parameters)
        pecan.abort(
            400, _("Missing required parameter(s): %s") % parameters_str)


def add_subcloud_to_database(context, payload):
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


def get_request_data(request: pecan.Request,
                     subcloud: models.Subcloud,
                     subcloud_file_contents: typing.Sequence):
    payload = dict()
    for f in subcloud_file_contents:
        if f in request.POST:
            file_item = request.POST[f]
            file_item.file.seek(0, os.SEEK_SET)
            contents = file_item.file.read()
            if f == consts.DEPLOY_CONFIG:
                fn = get_config_file_path(subcloud.name, f)
                upload_config_file(contents, fn, f)
                payload.update({f: fn})
            else:
                data = yaml.safe_load(contents.decode('utf8'))
                if f == consts.BOOTSTRAP_VALUES:
                    payload.update(data)
                else:
                    payload.update({f: data})
            del request.POST[f]
    payload.update(request.POST)
    return payload


def get_subcloud_db_install_values(subcloud):
    if not subcloud.data_install:
        msg = _("Failed to read data install from db")
        LOG.exception(msg)
        pecan.abort(400, msg)

    install_values = json.loads(subcloud.data_install)

    # mandatory install parameters
    mandatory_install_parameters = [
        'bootstrap_interface',
        'bootstrap_address',
        'bootstrap_address_prefix',
        'bmc_username',
        'bmc_address',
        'bmc_password',
    ]
    for p in mandatory_install_parameters:
        if p not in install_values:
            msg = _("Failed to get %s from data_install" % p)
            LOG.exception(msg)
            pecan.abort(400, msg)

    return install_values


def populate_payload_with_pre_existing_data(payload: dict,
                                            subcloud: models.Subcloud,
                                            mandatory_values: typing.Sequence):
    for value in mandatory_values:
        if value == consts.INSTALL_VALUES:
            if not payload.get(consts.INSTALL_VALUES):
                install_values = get_subcloud_db_install_values(subcloud)
                payload.update({value: install_values})
            else:
                validate_install_values(payload)
        elif value == consts.BOOTSTRAP_VALUES:
            filename = get_config_file_path(subcloud.name)
            LOG.info("Loading existing bootstrap values from: %s" % filename)
            try:
                existing_values = utils.load_yaml_file(filename)
            except FileNotFoundError:
                msg = _("Required %s file was not provided and it was not "
                        "previously available.") % value
                pecan.abort(400, msg)
            payload.update(existing_values)
        elif value == consts.DEPLOY_CONFIG:
            if not payload.get(consts.DEPLOY_CONFIG):
                fn = get_config_file_path(subcloud.name, value)
                if not os.path.exists(fn):
                    msg = _("Required %s file was not provided and it was not "
                            "previously available.") % consts.DEPLOY_CONFIG
                    pecan.abort(400, msg)
                payload.update({value: fn})
            get_common_deploy_files(payload, subcloud.software_version)


def pre_deploy_install(payload: dict,
                       subcloud: models.Subcloud):

    install_values = payload['install_values']

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
    matching_iso, err_msg = utils.get_matching_iso(payload['software_version'])
    if err_msg:
        LOG.exception(err_msg)
        pecan.abort(400, _(err_msg))
    LOG.info("Image in install_values is set to %s" % matching_iso)
    install_values['image'] = matching_iso

    # Update the install values in payload
    if not payload.get('bmc_password'):
        payload.update({'bmc_password': install_values.get('bmc_password')})
    payload.update({'install_values': install_values})