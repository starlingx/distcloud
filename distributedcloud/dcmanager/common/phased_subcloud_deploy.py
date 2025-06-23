#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import json
import os
import tarfile
import tempfile
import typing

import ipaddress
import netaddr
from oslo_log import log as logging
from oslo_utils import uuidutils
import pecan
import tsconfig.tsconfig as tsc

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache
from dccommon import utils as cutils
from dcmanager.common import consts
from dcmanager.common.context import RequestContext
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models

LOG = logging.getLogger(__name__)

ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS = (
    consts.ANSIBLE_CURRENT_VERSION_BASE_PATH
    + "/roles/bootstrap/validate-config/vars/main.yml"
)

FRESH_INSTALL_K8S_VERSION = "fresh_install_k8s_version"
KUBERNETES_VERSION = "kubernetes_version"

INSTALL_VALUES_ADDRESSES = [
    "bootstrap_address",
    "bmc_address",
    "nexthop_gateway",
    "network_address",
]

BOOTSTRAP_VALUES_ADDRESSES = [
    "bootstrap-address",
    "management_start_address",
    "management_end_address",
    "management_gateway_address",
    "systemcontroller_gateway_address",
    "external_oam_gateway_address",
    "external_oam_floating_address",
    "admin_floating_address",
    "admin_start_address",
    "admin_end_address",
    "admin_gateway_address",
]


def validate_bootstrap_values(payload: dict):
    name = payload.get("name")
    if not name:
        pecan.abort(400, _("name required"))

    system_mode = payload.get("system_mode")
    if not system_mode:
        pecan.abort(400, _("system_mode required"))

    # The admin network is optional, but takes precedence over the
    # management network for communication between the subcloud and
    # system controller if it is defined.
    admin_subnet = payload.get("admin_subnet", None)
    admin_start_ip = payload.get("admin_start_address", None)
    admin_end_ip = payload.get("admin_end_address", None)
    admin_gateway_ip = payload.get("admin_gateway_address", None)
    admin_floating_ip = payload.get("admin_floating_address", None)

    if (
        admin_floating_ip
        and not any([admin_start_ip, admin_end_ip])
        and system_mode == consts.SYSTEM_MODE_SIMPLEX
    ):
        admin_start_ip = admin_floating_ip
        admin_end_ip = admin_floating_ip
        payload["admin_start_address"] = admin_floating_ip
        payload["admin_end_address"] = admin_floating_ip

    if admin_floating_ip and admin_floating_ip != admin_start_ip:
        pecan.abort(400, _("admin_floating_address does not match admin_start_address"))

    if any([admin_subnet, admin_start_ip, admin_end_ip, admin_gateway_ip]):
        # If any admin parameter is defined, all admin parameters
        # should be defined.
        if not admin_subnet:
            pecan.abort(400, _("admin_subnet required"))
        if not admin_start_ip:
            pecan.abort(400, _("admin_start_address required"))
        if not admin_end_ip:
            pecan.abort(400, _("admin_end_address required"))
        if not admin_gateway_ip:
            pecan.abort(400, _("admin_gateway_address required"))

    management_subnet = payload.get("management_subnet")
    if not management_subnet:
        pecan.abort(400, _("management_subnet required"))

    management_start_ip = payload.get("management_start_address")
    if not management_start_ip:
        pecan.abort(400, _("management_start_address required"))

    management_end_ip = payload.get("management_end_address")
    if not management_end_ip:
        pecan.abort(400, _("management_end_address required"))

    management_gateway_ip = payload.get("management_gateway_address")
    if admin_gateway_ip and management_gateway_ip:
        pecan.abort(
            400,
            _(
                "admin_gateway_address and management_gateway_address cannot be "
                "specified at the same time"
            ),
        )
    elif not admin_gateway_ip and not management_gateway_ip:
        pecan.abort(400, _("management_gateway_address required"))

    systemcontroller_gateway_ip = payload.get("systemcontroller_gateway_address")
    if not systemcontroller_gateway_ip:
        pecan.abort(400, _("systemcontroller_gateway_address required"))

    external_oam_subnet = payload.get("external_oam_subnet")
    if not external_oam_subnet:
        pecan.abort(400, _("external_oam_subnet required"))

    external_oam_gateway_ip = payload.get("external_oam_gateway_address")
    if not external_oam_gateway_ip:
        pecan.abort(400, _("external_oam_gateway_address required"))

    external_oam_floating_ip = payload.get("external_oam_floating_address")
    if not external_oam_floating_ip:
        pecan.abort(400, _("external_oam_floating_address required"))


def validate_system_controller_deploy_status(operation: str):
    if utils.is_system_controller_deploying():
        message = (
            f"Subcloud {operation} is not allowed while the system controller is "
            "still undergoing software update."
        )
        pecan.abort(422, _(message))


def verify_boolean_str(value):
    if isinstance(value, str) and value in ["true", "false"]:
        return

    pecan.abort(
        400,
        _("Invalid boolean string: %s. Valid options are true and false.") % value,
    )


def validate_migrate_parameter(payload):
    migrate_str = payload.get("migrate")
    if migrate_str is None:
        return

    verify_boolean_str(migrate_str)

    if migrate_str == "false":
        return

    enroll_str = payload.get("enroll")
    if enroll_str is not None:
        verify_boolean_str(enroll_str)
        if enroll_str == "true":
            pecan.abort(400, _("migrate with enroll is not allowed"))

    if consts.DEPLOY_CONFIG in payload:
        pecan.abort(400, _("migrate with deploy-config is not allowed"))


def validate_enroll_parameter(payload):
    enroll_str = payload.get("enroll")

    if enroll_str is None:
        return

    verify_boolean_str(enroll_str)

    if enroll_str == "false":
        if dccommon_consts.CLOUD_INIT_CONFIG in payload:
            pecan.abort(400, _("cloud_init_config is not allowed with enroll=false"))
        else:
            return

    install_values = payload.get(consts.INSTALL_VALUES)
    if not install_values:
        pecan.abort(400, _("Install values is necessary for subcloud enrollment"))
    # Update the install values in payload
    if not payload.get("bmc_password"):
        payload.update({"bmc_password": install_values.get("bmc_password")})


def validate_tarball(contents, file_name):
    try:
        with tempfile.NamedTemporaryFile(delete=True) as tmp_file:
            tmp_file.write(contents)
            tmp_file.flush()
            if not tarfile.is_tarfile(tmp_file.name):
                pecan.abort(400, _("%s is not a valid tar archive.") % file_name)

    except (base64.binascii.Error, tarfile.TarError, OSError) as e:
        pecan.abort(400, _("Failed to validate %s: %s") % (file_name, str(e)))


def validate_secondary_parameter(payload, request):
    secondary_str = payload.get("secondary")
    migrate_str = payload.get("migrate")
    if secondary_str is not None:
        if secondary_str not in ["true", "false"]:
            pecan.abort(
                400,
                _("The secondary option is invalid, valid options are true and false."),
            )
        if consts.DEPLOY_CONFIG in request.POST:
            pecan.abort(400, _("secondary with deploy-config is not allowed"))
        if migrate_str is not None:
            pecan.abort(400, _("secondary with migrate is not allowed"))


def validate_systemcontroller_gateway_address(
    systemcontroller_gateway_address: str, payload
) -> None:
    """Aborts the request if the systemcontroller gateway address is invalid

    :param systemcontroller_gateway_address: systemcontroller gateway address
    :param payload: payload consisting of subcloud's management_subnet or admin_subnet
    """
    # Ensure primary systemcontroller gateway is in management subnets
    # for the systemcontroller region.
    #
    # system-controller to subcloud management communication is routed
    # through primary systemcontroller_gateway_address. The IP family
    # of primary systemcontroller_gateway_address must match with subcloud's primary
    # management subnet. Also Ensure primary systemcontroller gateway is in either
    # primary or secondary management subnet for the systemcontroller, depending upon
    # IP family.
    #
    # Use case example.
    # systemcontroller: IPv4 primary, IPv6 secondary management network
    # subcloud1: IPv4 only management network and IPv4 systemcontroller_gateway_address
    # subcloud2: IPv6 only management network and IPv6 systemcontroller_gateway_address
    # subcloud3: IPv4 primary, IPv6 secondary management network
    #            and IPv4 systemcontroller_gateway_address
    # subcloud4: IPv6 primary, IPv4 secondary management network
    #            and IPv6 systemcontroller_gateway_address

    # primary of systemcontroller_gateway_address
    gateway_address = systemcontroller_gateway_address.split(",")[0]
    try:
        gateway_ip_version = netaddr.IPAddress(gateway_address).version
    except Exception as e:
        LOG.exception(e)
        pecan.abort(400, _("systemcontroller_gateway_address invalid: %s") % e)

    subcloud_primary_mgmt_subnet = utils.get_primary_management_subnet(payload)
    admin_subnet = payload.get("admin_subnet", None)
    try:
        subcloud_subnet_ip_version = netaddr.IPNetwork(
            subcloud_primary_mgmt_subnet
        ).version
    except Exception as e:
        LOG.exception(e)
        if admin_subnet:
            pecan.abort(400, _("admin_subnet invalid: %s") % e)
        pecan.abort(400, _("management_subnet invalid: %s") % e)

    if gateway_ip_version != subcloud_subnet_ip_version:
        pecan.abort(
            400,
            _("systemcontroller_gateway_address invalid: Expected IPv%s")
            % subcloud_subnet_ip_version,
        )

    management_address_pools = get_network_address_pools()
    # choose address pool that matches IP family of systemcontroller gateway
    try:
        management_address_pool = utils.get_pool_by_ip_family(
            management_address_pools, gateway_ip_version
        )
    except Exception as e:
        error_msg = (
            "systemcontroller_gateway_address IP family is not aligned "
            "with system controller management"
        )
        LOG.exception(error_msg)
        pecan.abort(400, _("%s: %s") % (error_msg, e))

    systemcontroller_subnet_str = "%s/%d" % (
        management_address_pool.network,
        management_address_pool.prefix,
    )
    systemcontroller_subnet = [netaddr.IPNetwork(systemcontroller_subnet_str)]
    try:
        systemcontroller_gw_ips = utils.validate_address_str(
            gateway_address, systemcontroller_subnet
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("systemcontroller_gateway_address invalid: %s") % e)

    # Ensure systemcontroller gateway is not within the actual
    # management subnet address pool to prevent address collision.
    mgmt_address_start = netaddr.IPAddress(management_address_pool.ranges[0][0])
    mgmt_address_end = netaddr.IPAddress(management_address_pool.ranges[0][1])
    if (systemcontroller_gw_ips[0] >= mgmt_address_start) and (
        systemcontroller_gw_ips[0] <= mgmt_address_end
    ):
        pecan.abort(
            400,
            _(
                "systemcontroller_gateway_address invalid, "
                "is within management pool: %(start)s - %(end)s"
            )
            % {"start": mgmt_address_start, "end": mgmt_address_end},
        )


def validate_subcloud_config(
    context, payload, operation=None, ignore_conflicts_with=None
):
    """Check whether subcloud config is valid."""

    # Validate the name
    if payload.get("name").isdigit():
        pecan.abort(400, _("name must contain alphabetic characters"))

    # If a subcloud group is not passed, use the default
    group_id = payload.get("group_id", consts.DEFAULT_SUBCLOUD_GROUP_ID)

    if cutils.is_system_controller_region(payload.get("name")):
        pecan.abort(
            400,
            _("name cannot be %(bad_name1)s or %(bad_name2)s")
            % {
                "bad_name1": cutils.get_region_one_name,
                "bad_name2": dccommon_consts.SYSTEM_CONTROLLER_NAME,
            },
        )

    admin_subnet = payload.get("admin_subnet", None)
    admin_start_ip = payload.get("admin_start_address", None)
    admin_end_ip = payload.get("admin_end_address", None)
    admin_gateway_ip = payload.get("admin_gateway_address", None)

    # Parse/validate the management subnet
    subcloud_subnets = []
    subclouds = db_api.subcloud_get_all(context)
    for subcloud in subclouds:
        # Ignore management subnet conflict with the subcloud specified by
        # ignore_conflicts_with
        if ignore_conflicts_with and (subcloud.id == ignore_conflicts_with.id):
            continue
        subcloud_subnets.append(netaddr.IPNetwork(subcloud.management_subnet))

    MIN_MANAGEMENT_SUBNET_SIZE = 7
    # subtract 3 for network, gateway and broadcast addresses.
    MIN_MANAGEMENT_ADDRESSES = MIN_MANAGEMENT_SUBNET_SIZE - 3

    management_subnets = []
    try:
        management_subnets = utils.validate_network_str(
            payload.get("management_subnet"),
            minimum_size=MIN_MANAGEMENT_SUBNET_SIZE,
            existing_networks=subcloud_subnets,
            operation=operation,
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("management_subnet invalid: %s") % e)

    # Parse/validate the start/end addresses
    management_start_ips = []
    try:
        management_start_ips = utils.validate_address_str(
            payload.get("management_start_address"), management_subnets
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("management_start_address invalid: %s") % e)

    management_end_ips = []
    try:
        management_end_ips = utils.validate_address_str(
            payload.get("management_end_address"), management_subnets
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("management_end_address invalid: %s") % e)

    for start_ip, end_ip in zip(management_start_ips, management_end_ips):
        if start_ip > end_ip:
            pecan.abort(
                400, _("management_start_address greater than management_end_address")
            )

        if netaddr.IPRange(start_ip, end_ip).size < MIN_MANAGEMENT_ADDRESSES:
            pecan.abort(
                400,
                _("management address range must contain at least %d addresses")
                % MIN_MANAGEMENT_ADDRESSES,
            )

    # Parse/validate the gateway
    # management_gateway_address is validated against management_subnets.
    management_gateway_ips = []
    if not admin_gateway_ip:
        try:
            management_gateway_ips = utils.validate_address_str(
                payload.get("management_gateway_address"), management_subnets
            )
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("management_gateway_address invalid: %s") % e)

    system_mode = payload.get("system_mode")
    if not system_mode:
        pecan.abort(400, _("system_mode required"))

    validate_admin_network_config(
        admin_subnet,
        admin_start_ip,
        admin_end_ip,
        admin_gateway_ip,
        existing_subclouds=subclouds,
        operation=operation,
        system_mode=system_mode,
    )

    # Ensure subcloud management gateway is not within the actual subcloud
    # management subnet address pool for consistency with the
    # systemcontroller gateway restriction below. Address collision
    # is not a concern as the address is added to sysinv.

    if admin_start_ip:
        subcloud_mgmt_address_start = [
            netaddr.IPAddress(admin_start) for admin_start in admin_start_ip.split(",")
        ]
    else:
        subcloud_mgmt_address_start = management_start_ips
    if admin_end_ip:
        subcloud_mgmt_address_end = [
            netaddr.IPAddress(admin_end) for admin_end in admin_end_ip.split(",")
        ]
    else:
        subcloud_mgmt_address_end = management_end_ips
    if admin_gateway_ip:
        subcloud_mgmt_gw_ip = [
            netaddr.IPAddress(admin_gateway)
            for admin_gateway in admin_gateway_ip.split(",")
        ]
    else:
        subcloud_mgmt_gw_ip = management_gateway_ips

    for start_ip, end_ip, gateway_ip in zip(
        subcloud_mgmt_address_start, subcloud_mgmt_address_end, subcloud_mgmt_gw_ip
    ):
        if start_ip <= gateway_ip <= end_ip:
            pecan.abort(
                400,
                _(
                    "%(network)s_gateway_address invalid, "
                    "is within management pool: %(start)s - %(end)s"
                )
                % {
                    "network": "admin" if admin_gateway_ip else "management",
                    "start": start_ip,
                    "end": end_ip,
                },
            )

    validate_systemcontroller_gateway_address(
        payload.get("systemcontroller_gateway_address"), payload
    )

    validate_oam_network_config(
        payload.get("external_oam_subnet"),
        payload.get("external_oam_gateway_address"),
        payload.get("external_oam_floating_address"),
        subcloud_subnets,
    )
    validate_group_id(context, group_id)


def check_range_overlaps(networks1, networks2):
    for n1 in networks1:
        for n2 in networks2:
            if n1.overlaps(n2):
                return True
    return False


def validate_admin_network_config(
    admin_subnet_str,
    admin_start_address_str,
    admin_end_address_str,
    admin_gateway_address_str,
    existing_subclouds=None,
    operation=None,
    system_mode=None,
):
    """validate whether admin network configuration is valid"""

    if not (
        admin_subnet_str
        or admin_start_address_str
        or admin_end_address_str
        or admin_gateway_address_str
    ):
        return

    if not existing_subclouds:
        existing_subclouds = []

    MIN_ADMIN_SUBNET_SIZE = 3 if system_mode == consts.SYSTEM_MODE_SIMPLEX else 5
    # subtract 3 for network, gateway and broadcast addresses.
    MIN_ADMIN_ADDRESSES = MIN_ADMIN_SUBNET_SIZE - 3

    admin_subnets = []
    try:
        # Use None as 'existing_networks' so the overlapping subnet
        # validation is not executed. For the admin network, we
        # perform a validation below to ensure the ranges of
        # the management start <-> end are unique per subcloud,
        # rather than the uniqueness of the entire subnet.
        admin_subnets = utils.validate_network_str(
            admin_subnet_str,
            minimum_size=MIN_ADMIN_SUBNET_SIZE,
            operation=operation,
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("admin_subnet invalid: %s") % e)

    # Parse/validate the start/end addresses
    admin_start_ips = []
    try:
        admin_start_ips = utils.validate_address_str(
            admin_start_address_str, admin_subnets
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("admin_start_address invalid: %s") % e)

    admin_end_ips = []
    try:
        admin_end_ips = utils.validate_address_str(admin_end_address_str, admin_subnets)
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("admin_end_address invalid: %s") % e)

    for start_ip, end_ip in zip(admin_start_ips, admin_end_ips):
        if start_ip > end_ip:
            pecan.abort(400, _("admin_start_address greater than admin_end_address"))

        if netaddr.IPRange(start_ip, end_ip).size < MIN_ADMIN_ADDRESSES:
            pecan.abort(
                400,
                _("admin address range must contain at least %d addresses")
                % MIN_ADMIN_ADDRESSES,
            )

        s0_nets = list(
            ipaddress.summarize_address_range(
                ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip)
            )
        )
        for subcloud in existing_subclouds:
            s1_nets = list(
                ipaddress.summarize_address_range(
                    ipaddress.ip_address(subcloud.management_start_ip),
                    ipaddress.ip_address(subcloud.management_end_ip),
                )
            )
            if check_range_overlaps(s0_nets, s1_nets):
                pecan.abort(
                    400,
                    _("Admin address range overlaps with that of subcloud %s")
                    % subcloud.name,
                )

    # Parse/validate the gateway
    # admin_gateway_address is validated against admin_subnets.
    try:
        utils.validate_address_str(admin_gateway_address_str, admin_subnets)
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("admin_gateway_address invalid: %s") % e)

    admin_gateway_ips = [
        netaddr.IPAddress(admin_gw) for admin_gw in admin_gateway_address_str.split(",")
    ]
    for start_ip, end_ip, gateway_ip in zip(
        admin_start_ips, admin_end_ips, admin_gateway_ips
    ):
        if start_ip <= gateway_ip <= end_ip:
            pecan.abort(
                400,
                _(
                    "admin_gateway_address invalid, "
                    "is within admin pool: %(start)s - %(end)s"
                )
                % {
                    "start": start_ip,
                    "end": end_ip,
                },
            )


def validate_oam_network_config(
    external_oam_subnet_str,
    external_oam_gateway_address_str,
    external_oam_floating_address_str,
    existing_networks,
):
    """validate whether oam network configuration is valid"""

    # Parse/validate the oam subnet
    MIN_OAM_SUBNET_SIZE = 3
    oam_subnets = []
    try:
        oam_subnets = utils.validate_network_str(
            external_oam_subnet_str,
            minimum_size=MIN_OAM_SUBNET_SIZE,
            existing_networks=existing_networks,
        )
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("external_oam_subnet invalid: %s") % e)

    # Parse/validate the addresses
    try:
        utils.validate_address_str(external_oam_gateway_address_str, oam_subnets)
    except exceptions.ValidateFail as e:
        LOG.exception(e)
        pecan.abort(400, _("oam_gateway_address invalid: %s") % e)

    try:
        utils.validate_address_str(external_oam_floating_address_str, oam_subnets)
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


def get_sysinv_client() -> SysinvClient:
    region_name = cutils.get_region_one_name()
    admin_session = EndpointCache.get_admin_session()
    return SysinvClient(region_name, admin_session)


def get_network_address_pools(network="management"):
    """Get the region network address pools"""
    sysinv_client = get_sysinv_client()
    if network == "admin":
        return sysinv_client.get_admin_address_pools()
    return sysinv_client.get_management_address_pools()


def validate_install_values(payload, subcloud=None):
    """Validate install values if 'install_values' is present in payload.

    The image in payload install values is optional, and if not provided,
    the image is set to the available active/inactive load image.

    :return boolean: True if bmc install requested, otherwise False
    """
    install_values = payload.get("install_values")
    if not install_values:
        return

    original_install_values = None
    if subcloud:
        if subcloud.data_install:
            original_install_values = json.loads(subcloud.data_install)

    bmc_password = payload.get("bmc_password")
    if not bmc_password:
        pecan.abort(400, _("subcloud bmc_password required"))
    try:
        base64.b64decode(bmc_password).decode("utf-8")
    except Exception:
        msg = _(
            "Failed to decode subcloud bmc_password, "
            "verify the password is base64 encoded"
        )
        LOG.exception(msg)
        pecan.abort(400, msg)
    payload["install_values"].update({"bmc_password": bmc_password})

    software_version = payload.get("software_version")
    if not software_version and subcloud:
        software_version = subcloud.software_version
    if "software_version" in install_values:
        install_software_version = str(install_values.get("software_version"))
        if software_version and software_version != install_software_version:
            pecan.abort(
                400,
                _(
                    "The software_version value %s in the install values "
                    "yaml file does not match with the specified/current "
                    "software version of %s. Please correct or remove "
                    "this parameter from the yaml file and try again."
                )
                % (install_software_version, software_version),
            )
    else:
        # Only install_values payload will be passed to the subcloud
        # installation backend methods. The software_version is required by
        # the installation, so it cannot be absent in the install_values.
        LOG.debug("software_version (%s) is added to install_values" % software_version)
        payload["install_values"].update({"software_version": software_version})

    if "persistent_size" in install_values:
        persistent_size = install_values.get("persistent_size")
        if not isinstance(persistent_size, int):
            pecan.abort(
                400,
                _(
                    "The install value persistent_size (in MB) must "
                    "be a whole number greater than or equal to %s"
                )
                % consts.DEFAULT_PERSISTENT_SIZE,
            )
        if persistent_size < consts.DEFAULT_PERSISTENT_SIZE:
            # the expected value is less than the default. so throw an error.
            pecan.abort(
                400,
                _("persistent_size of %s MB is less than the permitted minimum %s MB")
                % (str(persistent_size), consts.DEFAULT_PERSISTENT_SIZE),
            )

    if "hw_settle" in install_values:
        hw_settle = install_values.get("hw_settle")
        if not isinstance(hw_settle, int):
            pecan.abort(
                400,
                _(
                    "The install value hw_settle (in seconds) must "
                    "be a whole number greater than or equal to 0"
                ),
            )
        if hw_settle < 0:
            pecan.abort(
                400, _("hw_settle of %s seconds is less than 0") % (str(hw_settle))
            )

    if "extra_boot_params" in install_values:
        # Validate 'extra_boot_params' boot parameter
        # Note: this must be a single string (no spaces). If
        # multiple boot parameters are required they can be
        # separated by commas. They will be split into separate
        # arguments by the miniboot.cfg kickstart.
        extra_boot_params = install_values.get("extra_boot_params")
        if extra_boot_params in ("", None, "None"):
            msg = "The install value extra_boot_params must not be empty."
            pecan.abort(400, _(msg))
        if " " in extra_boot_params:
            msg = (
                f"Invalid install value 'extra_boot_params={extra_boot_params}'. "
                "Spaces are not allowed (use ',' to separate multiple arguments)"
            )
            pecan.abort(400, _(msg))

    for k in dccommon_consts.MANDATORY_INSTALL_VALUES:
        if k not in install_values:
            if original_install_values:
                pecan.abort(
                    400,
                    _("Mandatory install value %s not present, existing %s in DB: %s")
                    % (k, k, original_install_values.get(k)),
                )
            else:
                pecan.abort(400, _("Mandatory install value %s not present") % k)

    # check for the image at load vault load location
    matching_iso, err_msg = utils.get_matching_iso(software_version)
    if err_msg:
        LOG.exception(err_msg)
        pecan.abort(400, _(err_msg))
    LOG.info("Image in install_values is set to %s" % matching_iso)
    payload["install_values"].update({"image": matching_iso})

    if install_values["install_type"] not in list(
        range(dccommon_consts.SUPPORTED_INSTALL_TYPES)
    ):
        pecan.abort(400, _("install_type invalid: %s") % install_values["install_type"])

    try:
        ip_version = netaddr.IPAddress(install_values["bootstrap_address"]).version
    except netaddr.AddrFormatError as e:
        LOG.exception(e)
        pecan.abort(400, _("bootstrap_address invalid: %s") % e)

    try:
        bmc_address = netaddr.IPAddress(install_values["bmc_address"])
    except netaddr.AddrFormatError as e:
        LOG.exception(e)
        pecan.abort(400, _("bmc_address invalid: %s") % e)

    if bmc_address.version != ip_version:
        pecan.abort(
            400, _("bmc_address and bootstrap_address must be the same IP version")
        )

    oam_ip_version = None
    oam_subnet_str = payload.get("external_oam_subnet", None)
    if oam_subnet_str:
        oam_ip_version = netaddr.IPNetwork(oam_subnet_str.split(",")[0]).version
    elif subcloud:
        oam_ip_version = int(subcloud.external_oam_subnet_ip_family)
    if oam_ip_version and bmc_address.version != oam_ip_version:
        pecan.abort(
            400,
            _("bmc_address and primary OAM network must be the same IP version"),
        )

    if "nexthop_gateway" in install_values:
        try:
            gateway_ip = netaddr.IPAddress(install_values["nexthop_gateway"])
        except netaddr.AddrFormatError as e:
            LOG.exception(e)
            pecan.abort(400, _("nexthop_gateway invalid: %s") % e)
        if gateway_ip.version != ip_version:
            pecan.abort(
                400,
                _("nexthop_gateway and bootstrap_address must be the same IP version"),
            )

    if "network_address" in install_values and "nexthop_gateway" not in install_values:
        pecan.abort(
            400, _("nexthop_gateway is required when network_address is present")
        )

    if "nexthop_gateway" and "network_address" in install_values:
        if "network_mask" not in install_values:
            pecan.abort(
                400,
                _("The network mask is required when network address is present"),
            )

        network_str = (
            install_values["network_address"]
            + "/"
            + str(install_values["network_mask"])
        )
        try:
            networks = utils.validate_network_str(network_str, 1)
        except exceptions.ValidateFail as e:
            LOG.exception(e)
            pecan.abort(400, _("network address invalid: %s") % e)

        if networks[0].version != ip_version:
            pecan.abort(
                400,
                _("network address and bootstrap address must be the same IP version"),
            )

    if "rd.net.timeout.ipv6dad" in install_values:
        try:
            ipv6dad_timeout = int(install_values["rd.net.timeout.ipv6dad"])
            if ipv6dad_timeout <= 0:
                pecan.abort(
                    400,
                    _("rd.net.timeout.ipv6dad must be greater than 0: %d")
                    % ipv6dad_timeout,
                )
        except ValueError as e:
            LOG.exception(e)
            pecan.abort(400, _("rd.net.timeout.ipv6dad invalid: %s") % e)

    if "rvmc_debug_level" in install_values:
        try:
            rvmc_debug_level = int(install_values["rvmc_debug_level"])
            if rvmc_debug_level < 0 or rvmc_debug_level > 4:
                pecan.abort(
                    400, _("rvmc_debug_level must be an integer between 0 and 4.")
                )
        except ValueError as e:
            LOG.exception(e)
            pecan.abort(400, _("Invalid value of rvmc_debug_level: %s") % e)


def validate_k8s_version(payload):
    """Validate k8s version.

    If the specified release in the payload is not the active release,
    the kubernetes_version value if specified in the subcloud bootstrap
    yaml file must be of the same value as fresh_install_k8s_version of
    the specified release.
    """
    software_version = payload["software_version"]
    if software_version == tsc.SW_VERSION:
        return

    kubernetes_version = payload.get(KUBERNETES_VERSION)
    if kubernetes_version:
        try:
            bootstrap_var_file = utils.get_playbook_for_software_version(
                ANSIBLE_BOOTSTRAP_VALIDATE_CONFIG_VARS, software_version
            )
            fresh_install_k8s_version = utils.get_value_from_yaml_file(
                bootstrap_var_file, FRESH_INSTALL_K8S_VERSION
            )
            if not fresh_install_k8s_version:
                pecan.abort(
                    400,
                    _("%s not found in %s")
                    % (FRESH_INSTALL_K8S_VERSION, bootstrap_var_file),
                )
            if kubernetes_version != fresh_install_k8s_version:
                pecan.abort(
                    400,
                    _(
                        "The kubernetes_version value (%s) specified in the subcloud "
                        "bootstrap yaml file doesn't match fresh_install_k8s_version "
                        "value (%s) of the specified release %s"
                    )
                    % (kubernetes_version, fresh_install_k8s_version, software_version),
                )
        except exceptions.PlaybookNotFound:
            pecan.abort(
                400,
                _(
                    "The bootstrap playbook validate-config vars "
                    "not found for %s software version"
                )
                % software_version,
            )


def validate_sysadmin_password(payload: dict):
    sysadmin_password = payload.get("sysadmin_password")
    if not sysadmin_password:
        pecan.abort(400, _("subcloud sysadmin_password required"))
    try:
        payload["sysadmin_password"] = base64.b64decode(sysadmin_password).decode(
            "utf-8"
        )
    except Exception:
        msg = _(
            "Failed to decode subcloud sysadmin_password, "
            "verify the password is base64 encoded"
        )
        LOG.exception(msg)
        pecan.abort(400, msg)


def format_ip_address(payload):
    """Format IP addresses in 'bootstrap_values' and 'install_values'.

    The IPv6 addresses can be represented in multiple ways. Format and
    update the IP addresses in payload before saving it to database.
    """
    if consts.INSTALL_VALUES in payload:
        for k in INSTALL_VALUES_ADDRESSES:
            if k in payload[consts.INSTALL_VALUES]:
                try:
                    address = netaddr.IPAddress(
                        payload[consts.INSTALL_VALUES].get(k)
                    ).format()
                except netaddr.AddrFormatError as e:
                    LOG.exception(e)
                    pecan.abort(400, _("%s invalid: %s") % (k, e))
                payload[consts.INSTALL_VALUES].update({k: address})

    for k in BOOTSTRAP_VALUES_ADDRESSES:
        if k in payload:
            addresses = []
            for k_value in payload.get(k).split(","):
                try:
                    address = netaddr.IPAddress(k_value).format()
                    addresses.append(address)
                except netaddr.AddrFormatError as e:
                    LOG.exception(e)
                    pecan.abort(400, _("%s invalid: %s") % (k, e))
            payload.update({k: ",".join(addresses)})


def upload_deploy_config_file(request, payload):
    file_item = request.POST.get(consts.DEPLOY_CONFIG)
    if file_item is None:
        return

    filename = getattr(file_item, "filename", "")
    if not filename:
        pecan.abort(400, _("No %s file uploaded" % consts.DEPLOY_CONFIG))

    file_item.file.seek(0, os.SEEK_SET)
    contents = file_item.file.read()
    # the deploy config needs to upload to the override location
    fn = get_config_file_path(payload["name"], consts.DEPLOY_CONFIG)
    upload_config_file(contents, fn, consts.DEPLOY_CONFIG)
    payload[consts.DEPLOY_CONFIG] = fn
    get_common_deploy_files(payload, payload["software_version"])


def upload_cloud_init_config(request, payload):
    file_item = request.POST.get(dccommon_consts.CLOUD_INIT_CONFIG)
    if file_item is None:
        return

    filename = getattr(file_item, "filename", "")
    if not filename:
        pecan.abort(400, _("No cloud-init-config file uploaded"))

    file_item.file.seek(0, os.SEEK_SET)
    contents = file_item.file.read()
    validate_tarball(contents, filename)
    fn = get_config_file_path(payload["name"], dccommon_consts.CLOUD_INIT_CONFIG)
    upload_binary_file(contents, fn, filename)
    payload[dccommon_consts.CLOUD_INIT_CONFIG] = fn


def get_config_file_path(subcloud_name, config_file_type=None):
    basepath = dccommon_consts.ANSIBLE_OVERRIDES_PATH
    if config_file_type == consts.DEPLOY_CONFIG:
        filename = f"{subcloud_name}_{config_file_type}.yml"
    elif config_file_type == dccommon_consts.CLOUD_INIT_CONFIG:
        filename = f"{subcloud_name}_{config_file_type}.tar"
    elif config_file_type == consts.INSTALL_VALUES:
        basepath = os.path.join(basepath, subcloud_name)
        filename = f"{config_file_type}.yml"
    else:
        filename = f"{subcloud_name}.yml"
    file_path = os.path.join(basepath, filename)
    return file_path


def upload_binary_file(contents, file_path, filename):
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(contents)
    except Exception:
        msg = _("Failed to upload %s to %s" % (filename, file_path))
        LOG.exception(msg)
        pecan.abort(400, msg)


def upload_config_file(file_item, config_file, config_type):
    try:
        with open(config_file, "w") as f:
            f.write(file_item.decode("utf8"))
    except Exception:
        msg = _("Failed to upload %s file" % config_type)
        LOG.exception(msg)
        pecan.abort(400, msg)


def check_deploy_files_in_alternate_location(payload):
    for f in os.listdir(consts.ALTERNATE_DEPLOY_PLAYBOOK_DIR):
        if f.endswith(consts.DEPLOY_PLAYBOOK_POSTFIX):
            filename = os.path.join(consts.ALTERNATE_DEPLOY_PLAYBOOK_DIR, f)
            payload.update({consts.DEPLOY_PLAYBOOK: filename})
            break
    else:
        return False

    for f in os.listdir(consts.ALTERNATE_HELM_CHART_DIR):
        if consts.HELM_CHART_POSTFIX in str(f):
            filename = os.path.join(consts.ALTERNATE_HELM_CHART_DIR, f)
            payload.update({consts.DEPLOY_CHART: filename})
            break
    else:
        return False
    return True


def get_common_deploy_files(payload, software_version):
    missing_deploy_files = []
    for f in consts.DEPLOY_COMMON_FILE_OPTIONS:
        # Skip the prestage_images option as it is not relevant in this context
        if f == consts.DEPLOY_PRESTAGE:
            continue
        if f == consts.DEPLOY_OVERRIDES:
            continue
        filename = None
        dir_path = os.path.join(dccommon_consts.DEPLOY_DIR, software_version)
        if os.path.isdir(dir_path):
            filename = utils.get_filename_by_prefix(dir_path, f + "_")
        if not filename:
            missing_deploy_files.append(f)
        else:
            payload.update({f: os.path.join(dir_path, filename)})
    if missing_deploy_files:
        if check_deploy_files_in_alternate_location(payload):
            payload.update({"user_uploaded_artifacts": False})
        else:
            missing_deploy_files_str = ", ".join(missing_deploy_files)
            msg = _("Missing required deploy files: %s" % missing_deploy_files_str)
            pecan.abort(400, msg)
    else:
        payload.update({"user_uploaded_artifacts": True})


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
        parameters_str = ", ".join(missing_parameters)
        pecan.abort(400, _("Missing required parameter(s): %s") % parameters_str)


def add_subcloud_to_database(context, payload):
    # if group_id has been omitted from payload, use 'Default'.
    group_id = payload.get("group_id", consts.DEFAULT_SUBCLOUD_GROUP_ID)
    data_install = None
    if "install_values" in payload:
        data_install = json.dumps(payload["install_values"])

    LOG.info(
        "Creating subcloud %s with region: %s",
        payload.get("name"),
        payload.get("region_name"),
    )

    subcloud = db_api.subcloud_create(
        context,
        payload["name"],
        payload.get("description"),
        payload.get("location"),
        payload.get("software_version"),
        utils.get_primary_management_subnet(payload),
        utils.get_primary_management_gateway_address(payload),
        utils.get_primary_management_start_address(payload),
        utils.get_primary_management_end_address(payload),
        utils.get_primary_systemcontroller_gateway_address(payload),
        str(utils.get_primary_oam_address_ip_family(payload)),
        consts.DEPLOY_STATE_NONE,
        consts.ERROR_DESC_EMPTY,
        payload["region_name"],
        False,
        group_id,
        data_install=data_install,
    )
    return subcloud


def is_initial_deployment(subcloud_name: str) -> bool:
    """Get initial deployment flag from inventory file"""

    postfix = consts.INVENTORY_FILE_POSTFIX
    filename = utils.get_ansible_filename(subcloud_name, postfix)

    # Assume initial deployment if inventory file is missing
    if not os.path.exists(filename):
        return True

    content = utils.load_yaml_file(filename)
    initial_deployment = content["all"]["vars"].get("initial_deployment")
    return initial_deployment


def update_payload_with_bootstrap_address(payload, subcloud: models.Subcloud):
    """Add bootstrap address to payload if not present already"""

    if payload.get(consts.BOOTSTRAP_ADDRESS):
        return
    if subcloud.data_install:
        data_install = json.loads(subcloud.data_install)
        bootstrap_address = data_install["bootstrap_address"]
    else:
        overrides_filename = get_config_file_path(subcloud.name)
        msg = _(
            "The bootstrap-address was not provided and it was not "
            "previously available. Please provide it in the request "
            "or update the subcloud with install-values and try again."
        )
        if not os.path.exists(overrides_filename):
            pecan.abort(400, msg)
        content = utils.load_yaml_file(overrides_filename)
        bootstrap_address = content.get(consts.BOOTSTRAP_ADDRESS)
        if not bootstrap_address:
            pecan.abort(400, msg)
    payload[consts.BOOTSTRAP_ADDRESS] = bootstrap_address


def get_request_data(
    request: pecan.Request,
    subcloud: models.Subcloud,
    subcloud_file_contents: typing.Sequence,
):
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
                data = utils.yaml_safe_load(contents.decode("utf8"), f)
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

    for p in dccommon_consts.MANDATORY_INSTALL_VALUES:
        if p not in install_values:
            msg = _("Failed to get %s from data_install" % p)
            LOG.exception(msg)
            pecan.abort(400, msg)

    return install_values


def populate_payload_with_pre_existing_data(
    payload: dict, subcloud: models.Subcloud, mandatory_values: typing.Sequence
):
    software_version = payload.get("software_version", subcloud.software_version)
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
                msg = (
                    _(
                        "Required %s file was not provided and it was not "
                        "previously available."
                    )
                    % value
                )
                pecan.abort(400, msg)
            payload.update(dict(list(existing_values.items()) + list(payload.items())))
        elif value == consts.DEPLOY_CONFIG:
            if not payload.get(consts.DEPLOY_CONFIG):
                fn = get_config_file_path(subcloud.name, value)
                if not os.path.exists(fn):
                    msg = (
                        _(
                            "Required %s file was not provided and it was not "
                            "previously available."
                        )
                        % consts.DEPLOY_CONFIG
                    )
                    pecan.abort(400, msg)
                payload.update({value: fn})
            get_common_deploy_files(payload, software_version)


def pre_deploy_create(payload: dict, context: RequestContext, request: pecan.Request):
    if not payload:
        pecan.abort(400, _("Body required"))

    validate_bootstrap_values(payload)

    payload["software_version"] = utils.get_sw_version(payload.get("release"))

    validate_subcloud_name_availability(context, payload["name"])

    validate_system_controller_deploy_status("create")

    validate_subcloud_config(context, payload)

    # install_values of secondary subclouds are validated on peer site
    if consts.DEPLOY_STATE_SECONDARY in payload and utils.is_req_from_another_dc(
        request
    ):
        LOG.debug(
            f"Skipping install_values validation for subcloud {payload['name']}. "
            "Subcloud is secondary and request is from a peer site."
        )
    else:
        validate_install_values(payload)

    validate_k8s_version(payload)

    format_ip_address(payload)

    # Upload the deploy config files if it is included in the request
    # It has a dependency on the subcloud name, and it is called after
    # the name has been validated
    upload_deploy_config_file(request, payload)


def pre_deploy_install(payload: dict, validate_password=False):
    if validate_password:
        validate_sysadmin_password(payload)

    install_values = payload["install_values"]

    # If the software version of the subcloud is different from the
    # specified or active load, update the software version in install
    # value and delete the image path in install values, then the subcloud
    # will be installed using the image in dc_vault.
    if install_values.get("software_version") != payload["software_version"]:
        install_values["software_version"] = payload["software_version"]
        install_values.pop("image", None)

    # Confirm the specified or active load is still in dc-vault if
    # image not in install values, add the matching image into the
    # install values.
    matching_iso, err_msg = utils.get_matching_iso(payload["software_version"])
    if err_msg:
        LOG.exception(err_msg)
        pecan.abort(400, _(err_msg))
    LOG.info("Image in install_values is set to %s" % matching_iso)
    install_values["image"] = matching_iso

    # Update the install values in payload
    if not payload.get("bmc_password"):
        payload.update({"bmc_password": install_values.get("bmc_password")})
    payload.update({"install_values": install_values})


def pre_deploy_bootstrap(
    context: RequestContext,
    payload: dict,
    subcloud: models.Subcloud,
    has_bootstrap_values: bool,
    validate_password=True,
):
    if validate_password:
        validate_sysadmin_password(payload)

    update_payload_with_bootstrap_address(payload, subcloud)
    if has_bootstrap_values:
        # Need to validate the new values
        payload_name = payload.get("name")
        if payload_name != subcloud.name:
            pecan.abort(
                400,
                _(
                    "The bootstrap-values 'name' value (%s) "
                    "must match the current subcloud name (%s)"
                    % (payload_name, subcloud.name)
                ),
            )

        # Verify if payload contains all required bootstrap values
        validate_bootstrap_values(payload)

        # It's ok for the management subnet to conflict with itself since we
        # are only going to update it if it was modified, conflicts with
        # other subclouds are still verified.
        validate_subcloud_config(context, payload, ignore_conflicts_with=subcloud)
        format_ip_address(payload)

    # Patch status and fresh_install_k8s_version may have been changed
    # between deploy create and deploy bootstrap commands. Validate them
    # again:
    validate_system_controller_deploy_status("bootstrap")
    validate_k8s_version(payload)


def pre_deploy_config(payload: dict, subcloud: models.Subcloud, validate_password=True):
    if validate_password:
        validate_sysadmin_password(payload)

    update_payload_with_bootstrap_address(payload, subcloud)


def get_bootstrap_subcloud_name(request: pecan.Request):
    bootstrap_values = request.POST.get(consts.BOOTSTRAP_VALUES)
    bootstrap_sc_name = None
    if bootstrap_values is not None:
        bootstrap_values.file.seek(0, os.SEEK_SET)
        contents = bootstrap_values.file.read()
        data = utils.yaml_safe_load(contents.decode("utf8"), consts.BOOTSTRAP_VALUES)
        bootstrap_sc_name = data.get("name")

    return bootstrap_sc_name


def is_migrate_scenario(payload: dict):
    migrate = False
    migrate_str = payload.get("migrate")

    if migrate_str is not None:
        if migrate_str == "true":
            migrate = True
    return migrate


def generate_subcloud_unique_region(context: RequestContext, payload: dict):
    LOG.debug("Begin generate subcloud unique region for subcloud %s" % payload["name"])

    is_migrate = is_migrate_scenario(payload)
    migrate_sc_region = None
    subcloud_name = payload.get("name")

    if subcloud_name is None:
        msg = "Missing subcloud name"
        raise exceptions.InvalidParameterValue(err=msg)

    # If migration flag is present, tries to connect to subcloud to
    # get the region value
    if is_migrate:
        LOG.debug(
            "The scenario matches that of the subcloud migration, therefore it will "
            "try to obtain the value of the region from subcloud %s..."
            % payload["name"]
        )

        bootstrap_addr = payload.get("bootstrap-address")

        if bootstrap_addr is None:
            msg = (
                "Invalid bootstrap address %s to retrieve subcloud region "
                "from subcloud %s" % (bootstrap_addr, subcloud_name)
            )
            raise exceptions.InvalidParameterValue(err=msg)

        # It connects to the subcloud via the bootstrap-address IP and tries
        # to get the region from it
        LOG.info("Getting subcloud region from subcloud %s" % subcloud_name)
        migrate_sc_region, error = utils.get_region_from_subcloud_address(payload)
        if migrate_sc_region is None:
            msg = (
                "Cannot find subcloud's region from subcloud %s with "
                "address %s due to: %s" % (subcloud_name, bootstrap_addr, error)
            )
            raise exceptions.InvalidParameterValue(err=msg)
    else:
        LOG.debug(
            "The scenario matches that of creating a new subcloud, "
            "so a region will be generated randomly for subcloud %s..." % subcloud_name
        )
    while True:
        # If migrate flag is not present, creates a random region value
        if not is_migrate:
            subcloud_region = uuidutils.generate_uuid().replace("-", "")
        else:
            # In the migration/rehome scenario uses the region value
            # returned by queried subcloud
            subcloud_region = migrate_sc_region
        # Lookup region to check if exists
        try:
            db_api.subcloud_get_by_region_name(context, subcloud_region)
            LOG.info(
                "Subcloud region: %s already exists. Generating new one..."
                % (subcloud_region)
            )
            # In the migration scenario, it is intended to use the
            # same region that the current subcloud has, therefore
            # another region value cannot be generated.
            if is_migrate:
                LOG.error(
                    "Subcloud region to migrate: %s already exists "
                    "and it is not allowed to generate a new region "
                    "for a subcloud migration" % (subcloud_region)
                )
                raise exceptions.SubcloudAlreadyExists(region_name=subcloud_region)
        except exceptions.SubcloudRegionNameNotFound:
            break
        except Exception:
            message = (
                "Unable to generate subcloud region for subcloud %s" % subcloud_name
            )
            LOG.error(message)
            raise
    if not is_migrate:
        LOG.info(
            "Generated region for new subcloud %s: %s"
            % (subcloud_name, subcloud_region)
        )
    else:
        LOG.info(
            "Region for subcloud %s to be migrated: %s"
            % (subcloud_name, subcloud_region)
        )
    return subcloud_region


def subcloud_region_create(payload: dict, context: RequestContext):
    try:
        # Generates a unique region value
        payload["region_name"] = generate_subcloud_unique_region(context, payload)
    except Exception:
        # For logging purpose only
        msg = (
            "Unable to retrieve subcloud region while trying to connect "
            "to the subcloud %s with bootstrap address %s"
            % (payload.get("name"), payload.get("bootstrap-address"))
        )
        if not is_migrate_scenario(payload):
            msg = "Unable to generate subcloud region for subcloud %s" % payload.get(
                "name"
            )
        LOG.exception(msg)
        pecan.abort(400, _(msg))
