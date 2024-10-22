# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import datetime
import grp
import itertools
import json
import os
import pwd
import re
import resource as sys_resource
import string
import subprocess
from typing import List
from typing import Optional
from typing import Union
import uuid
import xml.etree.ElementTree as ElementTree

from keystoneauth1 import exceptions as keystone_exceptions
from keystoneclient.v3.client import Client as KeystoneClient
import netaddr
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import base64
import pecan
import requests
from retrying import retry
import tsconfig.tsconfig as tsc
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack import software_v1
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.drivers.openstack import vim
from dccommon import exceptions as dccommon_exceptions
from dccommon import kubeoperator
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)

DC_MANAGER_USERNAME = "root"
DC_MANAGER_GRPNAME = "root"

# Max lines output msg from logs
MAX_LINES_MSG = 10
REGION_VALUE_CMD = "grep " + consts.OS_REGION_NAME + " /etc/platform/openrc"

ABORT_UPDATE_STATUS = {
    consts.DEPLOY_STATE_INSTALLING: consts.DEPLOY_STATE_ABORTING_INSTALL,
    consts.DEPLOY_STATE_BOOTSTRAPPING: consts.DEPLOY_STATE_ABORTING_BOOTSTRAP,
    consts.DEPLOY_STATE_CONFIGURING: consts.DEPLOY_STATE_ABORTING_CONFIG,
    consts.DEPLOY_STATE_ABORTING_INSTALL: consts.DEPLOY_STATE_INSTALL_ABORTED,
    consts.DEPLOY_STATE_ABORTING_BOOTSTRAP: consts.DEPLOY_STATE_BOOTSTRAP_ABORTED,
    consts.DEPLOY_STATE_ABORTING_CONFIG: consts.DEPLOY_STATE_CONFIG_ABORTED,
}

ABORT_UPDATE_FAIL_STATUS = {
    consts.DEPLOY_STATE_ABORTING_INSTALL: consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_ABORTING_BOOTSTRAP: consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
    consts.DEPLOY_STATE_ABORTING_CONFIG: consts.DEPLOY_STATE_CONFIG_FAILED,
}

RESUME_PREP_UPDATE_STATUS = {
    consts.DEPLOY_PHASE_INSTALL: consts.DEPLOY_STATE_PRE_INSTALL,
    consts.DEPLOY_PHASE_BOOTSTRAP: consts.DEPLOY_STATE_PRE_BOOTSTRAP,
    consts.DEPLOY_PHASE_CONFIG: consts.DEPLOY_STATE_PRE_CONFIG,
}

RESUME_PREP_UPDATE_FAIL_STATUS = {
    consts.DEPLOY_PHASE_INSTALL: consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
    consts.DEPLOY_PHASE_BOOTSTRAP: consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
    consts.DEPLOY_PHASE_CONFIG: consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
}


def get_import_path(cls):
    return cls.__module__ + "." + cls.__name__


# Returns a iterator of tuples containing batch_size number of objects in each
def get_batch_projects(batch_size, project_list, fillvalue=None):
    args = [iter(project_list)] * batch_size
    return itertools.zip_longest(fillvalue=fillvalue, *args)


def validate_address_str(ip_address_str, networks):
    """Determine whether an dual-stack address is valid."""
    address_values = ip_address_str.split(",")

    if len(address_values) > 2:
        raise exceptions.ValidateFail("Invalid address - more than two IP addresses")

    ip_addresses = []
    for address_value in address_values:
        try:
            ip_address = netaddr.IPAddress(address_value)
            ip_addresses.append(ip_address)
        except Exception:
            raise exceptions.ValidateFail("Invalid address - not a valid IP address")

    if len(address_values) == 2 and ip_addresses[0].version == ip_addresses[1].version:
        raise exceptions.ValidateFail("Invalid address - dual-stack of same IP family")

    if len(ip_addresses) != len(networks):
        raise exceptions.ValidateFail(
            "Invalid address - Not of same size (single or dual-stack) with subnet"
        )

    for i, ip_address in enumerate(ip_addresses):
        if ip_address.version != networks[i].version:
            msg = (
                "Invalid IP version - must match network version "
                + ip_version_to_string(networks[i].version)
            )
            raise exceptions.ValidateFail(msg)
        elif ip_address == networks[i]:
            raise exceptions.ValidateFail("Cannot use network address")
        elif ip_address == networks[i].broadcast:
            raise exceptions.ValidateFail("Cannot use broadcast address")
        elif ip_address not in networks[i]:
            raise exceptions.ValidateFail(
                "Address must be in subnet %s" % str(networks[i])
            )
    return ip_addresses


def ip_version_to_string(ip_version):
    """Returns a string representation of ip_version."""
    if ip_version == 4:
        return "IPv4"
    elif ip_version == 6:
        return "IPv6"
    else:
        return "IP"


def validate_network_str(
    network_str, minimum_size, existing_networks=None, multicast=False, operation=None
):
    """Determine whether dual-stack network is valid."""
    network_values = network_str.split(",")

    if len(network_values) > 2:
        raise exceptions.ValidateFail("Invalid subnet - more than two IP subnets")

    networks = []
    for network_value in network_values:
        try:
            network = netaddr.IPNetwork(network_value)
            networks.append(network)
        except netaddr.AddrFormatError:
            raise exceptions.ValidateFail("Invalid subnet - not a valid IP subnet")

    if len(network_values) == 2 and networks[0].version == networks[1].version:
        raise exceptions.ValidateFail("Invalid subnet - dual-stack of same IP family")

    for network in networks:
        if network.size < minimum_size:
            raise exceptions.ValidateFail(
                "Subnet too small - must have at least %d addresses" % minimum_size
            )
        elif network.version == 6 and network.prefixlen < 64:
            raise exceptions.ValidateFail("IPv6 minimum prefix length is 64")
        elif existing_networks and operation != "redeploy":
            if any(network.ip in subnet for subnet in existing_networks):
                raise exceptions.ValidateFail(
                    "Subnet overlaps with another configured subnet"
                )
        elif multicast and not network.is_multicast():
            raise exceptions.ValidateFail("Invalid subnet - must be multicast")
    return networks


def validate_certificate_subject(subject):
    """Validate a certificate subject

    Duplicate the get_subject validation logic defined in:
    sysinv/api/controllers/v1/kube_rootca_update.py
    Returns a tuple of True, "" if the input is None
    Returns a tuple of True, "" if the input is valid
    Returns a tuple of False, "<error details>" if the input is invalid
    """
    if subject is None:
        return True, ""

    params_supported = ["C", "OU", "O", "ST", "CN", "L"]
    subject_pairs = re.findall(r"([^=]+=[^=]+)(?:\s|$)", subject)
    subject_dict = {}
    for pair_value in subject_pairs:
        key, value = pair_value.split("=")
        subject_dict[key] = value

    if not all([param in params_supported for param in subject_dict.keys()]):
        return False, (
            "There are parameters not supported for the certificate subject "
            "specification. The subject parameter has to be in the format of "
            "'C=<Country> ST=<State/Province> L=<Locality> O=<Organization> "
            "OU=<OrganizationUnit> CN=<commonName>"
        )
    if "CN" not in list(subject_dict.keys()):
        return False, (
            "The CN=<commonName> parameter is required to be "
            "specified in subject argument"
        )
    return True, ""


def validate_expiry_date(expiry_date):
    """Validate a certificate expiry date

    Duplicate the expiry_date validation logic defined in:
    sysinv/api/controllers/v1/kube_rootca_update.py
    Returns a tuple of True, "" if the input is None
    Returns a tuple of True, "" if the input is valid
    Returns a tuple of False, "<error details>" if the input is invalid
    """
    if expiry_date is None:
        return True, ""

    try:
        date = datetime.datetime.strptime(expiry_date, "%Y-%m-%d")
    except ValueError:
        return False, ("expiry_date %s doesn't match format YYYY-MM-DD" % expiry_date)

    delta = date - datetime.datetime.now()
    # we sum one day (24 hours) to accomplish the certificate expiry
    # during the day specified by the user
    duration = delta.days * 24 + 24

    # Cert-manager manages certificates and renew them some time
    # before it expires. Along this procedure we set renewBefore
    # parameter for 24h, so we are checking if the duration sent
    # has at least this amount of time. This is needed to avoid
    # cert-manager to block the creation of the resources.
    if duration <= 24:
        return False, (
            "New k8s rootCA should have at least 24 hours of validation before expiry."
        )
    return True, ""


# to do validate the quota limits
def validate_quota_limits(payload):
    for resource in payload:
        # Check valid resource name
        if resource not in itertools.chain(
            dccommon_consts.CINDER_QUOTA_FIELDS,
            dccommon_consts.NOVA_QUOTA_FIELDS,
            dccommon_consts.NEUTRON_QUOTA_FIELDS,
        ):
            raise exceptions.InvalidInputError
        # Check valid quota limit value in case for put/post
        if isinstance(payload, dict) and (
            not isinstance(payload[resource], int) or payload[resource] <= 0
        ):
            raise exceptions.InvalidInputError


def get_sw_update_strategy_extra_args(context, update_type=None):
    """Query an existing sw_update_strategy for its extra_args.

    :param context: request context object.
    :param update_type: filter the update strategy (defaults to None)
    :returns dict (returns an empty dictionary if no strategy exists)
    """
    try:
        sw_update_strategy = db_api.sw_update_strategy_get(
            context, update_type=update_type
        )
        return sw_update_strategy.extra_args
    except exceptions.NotFound:
        # return an empty dictionary if there is no strategy
        return {}


def get_sw_update_opts(context, for_sw_update=False, subcloud_id=None):
    """Get sw update options for a subcloud

    :param context: request context object.
    :param for_sw_update: return the default options if subcloud options
                            are empty. Useful for retrieving sw update
                            options on application of patch strategy.
    :param subcloud_id: id of subcloud.

    """

    if subcloud_id is None:
        # Requesting defaults. Return constants if no entry in db.
        sw_update_opts_ref = db_api.sw_update_opts_default_get(context)
        if not sw_update_opts_ref:
            sw_update_opts_dict = vim.SW_UPDATE_OPTS_CONST_DEFAULT
            return sw_update_opts_dict
    else:
        # requesting subcloud options
        sw_update_opts_ref = db_api.sw_update_opts_get(context, subcloud_id)
        if sw_update_opts_ref:
            subcloud_name = db_api.subcloud_get(context, subcloud_id).name
            return db_api.sw_update_opts_w_name_db_model_to_dict(
                sw_update_opts_ref, subcloud_name
            )
        elif for_sw_update:
            sw_update_opts_ref = db_api.sw_update_opts_default_get(context)
            if not sw_update_opts_ref:
                sw_update_opts_dict = vim.SW_UPDATE_OPTS_CONST_DEFAULT
                return sw_update_opts_dict
        else:
            raise exceptions.SubcloudPatchOptsNotFound(subcloud_id=subcloud_id)

    return db_api.sw_update_opts_w_name_db_model_to_dict(
        sw_update_opts_ref, dccommon_consts.SW_UPDATE_DEFAULT_TITLE
    )


def ensure_lock_path():
    # Determine the oslo_concurrency lock path:
    # 1) First, from the oslo_concurrency section of the config
    #    a) If not set via an option default or config file, oslo_concurrency
    #       sets it to the OSLO_LOCK_PATH env variable
    # 2) Then if not set, set it to a specific directory under
    #    tsc.VOLATILE_PATH

    if cfg.CONF.oslo_concurrency.lock_path:
        lock_path = cfg.CONF.oslo_concurrency.lock_path
    else:
        lock_path = os.path.join(tsc.VOLATILE_PATH, "dcmanager")

    if not os.path.isdir(lock_path):
        try:
            uid = pwd.getpwnam(DC_MANAGER_USERNAME).pw_uid
            gid = grp.getgrnam(DC_MANAGER_GRPNAME).gr_gid
            os.makedirs(lock_path)
            os.chown(lock_path, uid, gid)
            LOG.info("Created directory=%s" % lock_path)

        except OSError as e:
            LOG.exception("makedir %s OSError=%s encountered" % (lock_path, e))
            return None

    return lock_path


def synchronized(name, external=True, fair=False):
    if external:
        prefix = "DCManager-"
        lock_path = ensure_lock_path()
    else:
        prefix = None
        lock_path = None

    return lockutils.synchronized(
        name,
        lock_file_prefix=prefix,
        external=external,
        lock_path=lock_path,
        semaphores=None,
        delay=0.01,
        fair=fair,
    )


def get_filename_by_prefix(dir_path, prefix):
    """Returns the first filename found matching 'prefix' within 'dir_path'

    Note: returns base filename only - result does not include dir_path
    """
    for filename in os.listdir(dir_path):
        if filename.startswith(prefix):
            return filename
    return None


def get_ansible_host_ip_from_inventory(subcloud_name: str):
    """Get ansible host ip from inventory file for the specified subcloud"""

    postfix = consts.INVENTORY_FILE_POSTFIX
    filename = get_ansible_filename(subcloud_name, postfix)

    content = load_yaml_file(filename)
    bootstrap_address = (
        content["all"]["hosts"].get(subcloud_name, {}).get("ansible_host")
    )
    return bootstrap_address


def create_subcloud_inventory(subcloud, inventory_file, initial_deployment=False):
    """Create the ansible inventory file for the specified subcloud"""

    # Delete the file if it already exists
    delete_subcloud_inventory(inventory_file)

    with open(inventory_file, "w") as f_out_inventory:
        f_out_inventory.write(
            "---\n"
            "all:\n"
            "  vars:\n"
            "    ansible_ssh_user: sysadmin\n"
            '    ansible_ssh_extra_args: "-o UserKnownHostsFile=/dev/null"\n'
            "    initial_deployment: " + str(initial_deployment) + "\n"
            "  hosts:\n"
            "    " + subcloud["name"] + ":\n"
            "      ansible_host: " + subcloud["bootstrap-address"] + "\n"
        )


def create_subcloud_inventory_with_admin_creds(
    subcloud_name,
    inventory_file,
    subcloud_bootstrap_address,
    ansible_pass,
    initial_deployment=False,
):
    """Create the ansible inventory file for the specified subcloud.

    Includes ansible_become_pass attribute.
    """

    # Delete the file if it already exists
    delete_subcloud_inventory(inventory_file)

    with open(inventory_file, "w") as f_out_inventory:
        f_out_inventory.write(
            (
                "---\n"
                "all:\n"
                "  vars:\n"
                "    ansible_ssh_user: sysadmin\n"
                "    ansible_ssh_pass: {0}\n"
                "    ansible_become_pass: {0}\n"
                '    ansible_ssh_extra_args: "-o UserKnownHostsFile=/dev/null"\n'
                "    initial_deployment: " + str(initial_deployment) + "\n"
                "  hosts:\n"
                "    {1}:\n"
                "      ansible_host: {2}\n"
            ).format(ansible_pass, subcloud_name, subcloud_bootstrap_address)
        )


def delete_subcloud_inventory(inventory_file):
    """Delete the ansible inventory file for the specified subcloud"""

    # Delete the file if it exists
    if inventory_file and os.path.isfile(inventory_file):
        os.remove(inventory_file)


def get_vault_load_files(target_version):
    """Return a tuple for the ISO and SIG for this load version from the vault.

    The files can be imported to the vault using any name, but must end
    in 'iso' or 'sig'.
    : param target_version: The software version to search under the vault
    """
    vault_dir = "{}/{}/".format(dccommon_consts.SOFTWARE_VAULT_DIR, target_version)

    matching_iso = None
    matching_sig = None

    if os.path.isdir(vault_dir):
        for a_file in os.listdir(vault_dir):
            if a_file.lower().endswith(".iso"):
                matching_iso = os.path.join(vault_dir, a_file)
                continue
            elif a_file.lower().endswith(".sig"):
                matching_sig = os.path.join(vault_dir, a_file)
                continue
        # If no .iso or .sig is found, raise an exception
        if matching_iso is None:
            raise exceptions.VaultLoadMissingError(
                file_type=".iso", vault_dir=vault_dir
            )
        if matching_sig is None:
            raise exceptions.VaultLoadMissingError(
                file_type=".sig", vault_dir=vault_dir
            )

    # return the iso and sig for this load
    return (matching_iso, matching_sig)


def get_active_kube_version(kube_versions):
    """Returns the active (target) kubernetes from a list of versions"""

    matching_kube_version = None
    for kube in kube_versions:
        kube_dict = kube.to_dict()
        if kube_dict.get("target") and kube_dict.get("state") == "active":
            matching_kube_version = kube_dict.get("version")
            break
    return matching_kube_version


def select_available_kube_version(kube_versions, to_version):
    """Return selected kube version based on desired version

    If the desired "to_version" is higher than the highest "available" version
    then return the highest "available" version.
    If the desired "to_version" is "available", we want to select it.
    Otherwise we want to select the highest "available" kubernetes version.
    """
    # Check if the desired version is higher than the highest "available" version.
    for kube in reversed(kube_versions):
        kube_dict = kube.to_dict()
        if kube_dict.get("state") == "available":
            version = kube_dict.get("version")
            if kube_version_compare(version, to_version) == -1:
                return version
            else:
                break

    # Check if the desired version is "available"
    for kube in reversed(kube_versions):
        kube_dict = kube.to_dict()
        version = kube_dict.get("version")
        if kube_version_compare(version, to_version) == 0:
            if kube_dict.get("state") == "available":
                return version
            else:
                break

    # Return the highest "available" version
    for kube in reversed(kube_versions):
        kube_dict = kube.to_dict()
        if kube_dict.get("state") == "available":
            return kube_dict.get("version")

    # There are no "available" versions
    return None


def kube_version_compare(left, right):
    """Performs a cmp operation for two kubernetes versions

    Return -1, 0, or 1 if left is less, equal, or greater than right

    left and right are semver strings starting with the letter 'v'
    If either value is None, an exception is raised
    If the strings are not 'v'major.minor.micro, an exception is raised
    Note: This method supports shorter versions.  ex: v1.22
    When comparing different length tuples, additional fields are ignored.
    For example: v1.19 and v1.19.1 would be the same.
    """
    if left is None or right is None or left[0] != "v" or right[0] != "v":
        raise Exception(
            "Invalid kube version(s), left: (%s), right: (%s)" % (left, right)
        )
    # start the split at index 1 ('after' the 'v' character)
    l_val = tuple(map(int, (left[1:].split("."))))
    r_val = tuple(map(int, (right[1:].split("."))))
    # If the tuples are different length, convert both to the same length
    min_tuple = min(len(l_val), len(r_val))
    l_val = l_val[0:min_tuple]
    r_val = r_val[0:min_tuple]
    # The following is the same as cmp. Verified in python2 and python3
    # cmp does not exist in python3.
    return (l_val > r_val) - (l_val < r_val)


def system_peer_get_by_ref(context, peer_ref):
    """Handle getting a system peer by either UUID, or ID, or Name

    :param context: The request context
    :param peer_ref: Reference to the system peer, either an UUID or an ID or a Name
    """
    try:
        if peer_ref.isdigit():
            return db_api.system_peer_get(context, peer_ref)
        try:
            uuid.UUID(peer_ref)
            return db_api.system_peer_get_by_uuid(context, peer_ref)
        except ValueError:
            return db_api.system_peer_get_by_name(context, peer_ref)
    except (
        exceptions.SystemPeerNotFound,
        exceptions.SystemPeerUUIDNotFound,
        exceptions.SystemPeerNameNotFound,
    ):
        return None


def subcloud_peer_group_db_list_to_dict(peer_groups):
    return {
        "subcloud_peer_groups": [
            db_api.subcloud_peer_group_db_model_to_dict(peer_group)
            for peer_group in peer_groups
        ]
    }


def subcloud_get_by_ref(context, subcloud_ref):
    """Handle getting a subcloud by either name, or ID

    :param context: The request context
    :param subcloud_ref: Reference to the subcloud, either a name or an ID
    """
    try:
        return (
            db_api.subcloud_get(context, subcloud_ref)
            if subcloud_ref.isdigit()
            else db_api.subcloud_get_by_name(context, subcloud_ref)
        )
    except (exceptions.SubcloudNotFound, exceptions.SubcloudNameNotFound):
        return None


def subcloud_group_get_by_ref(context, group_ref):
    # Handle getting a group by either name, or ID
    if group_ref.isdigit():
        # Lookup subcloud group as an ID
        try:
            group = db_api.subcloud_group_get(context, group_ref)
        except exceptions.SubcloudGroupNotFound:
            return None
    else:
        # Lookup subcloud group as a name
        try:
            group = db_api.subcloud_group_get_by_name(context, group_ref)
        except exceptions.SubcloudGroupNameNotFound:
            return None
    return group


def subcloud_peer_group_get_by_ref(context, group_ref):
    """Handle getting a peer group by either name, or ID"""
    try:
        if group_ref.isdigit():
            # Lookup subcloud group as an ID
            group = db_api.subcloud_peer_group_get(context, group_ref)
        else:
            # Lookup subcloud group as a name
            group = db_api.subcloud_peer_group_get_by_name(context, group_ref)
    except (
        exceptions.SubcloudPeerGroupNotFound,
        exceptions.SubcloudPeerGroupNameNotFound,
    ):
        return None
    return group


def subcloud_db_list_to_dict(subclouds):
    return {
        "subclouds": [
            db_api.subcloud_db_model_to_dict(subcloud) for subcloud in subclouds
        ]
    }


def get_oam_floating_ip_primary(subcloud, sc_ks_client):
    """Get the subcloud's oam primary floating ip"""

    # First need to retrieve the Subcloud's Keystone session
    try:
        endpoint = sc_ks_client.endpoint_cache.get_endpoint("sysinv")
        sysinv_client = SysinvClient(
            subcloud.region_name, sc_ks_client.session, endpoint=endpoint
        )
        # We don't want to call sysinv_client.get_oam_address_pools()
        # here, as the subcloud's software version could be < 24.09.
        # As we are interested only on primary IP-stack, get_oam_addresses
        # supports this in any software_version.
        oam_addresses = sysinv_client.get_oam_addresses()
        if oam_addresses is not None:
            return oam_addresses.oam_floating_ip
        return None
    except (keystone_exceptions.EndpointNotFound, IndexError) as e:
        message = "Identity endpoint for subcloud: %s not found. %s" % (
            subcloud.name,
            e,
        )
        LOG.error(message)
    except dccommon_exceptions.OAMAddressesNotFound:
        message = "OAM addresses for subcloud: %s not found." % subcloud.name
        LOG.error(message)
    return None


def get_pool_by_ip_family(pools, ip_family):
    """Get the pool corresponding to ip family"""
    for pool in pools:
        if pool.family == ip_family:
            return pool

    raise exceptions.ValidateFail(f"IPv{ip_family} pool not found in pools {pools}")


def get_ansible_filename(subcloud_name, postfix=".yml"):
    """Build ansible filename using subcloud and given postfix"""
    ansible_filename = os.path.join(
        dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_name + postfix
    )
    return ansible_filename


def pre_check_management_affected_alarm(system_health):
    """Acceptable health conditions:

    a) subcloud is completely healthy (i.e. no failed checks)
    b) there is alarm but no management affecting alarm
    c) subcloud fails alarm check and it only has non-management
       affecting alarm(s)
    """
    failed_alarm_check = re.findall(r"No alarms: \[Fail\]", system_health)
    no_mgmt_alarms = re.findall(
        r"\[0\] of which are management affecting", system_health
    )
    if failed_alarm_check and not no_mgmt_alarms:
        return False
    return True


def is_subcloud_name_format_valid(name):
    """Validates subcloud name format

    Regex based on RFC 1123 subdomain validation

    param: name = Subcloud name
    returns True if name is valid, otherwise it returns false.
    """
    rex = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"

    pat = re.compile(rex)
    if re.fullmatch(pat, name):
        return True
    return False


# TODO(glyraper): Replace get_region_from_subcloud_address()
#  with get_region_name once all the subclouds support
#  '/v1/isystems/region_id' API
def get_region_from_subcloud_address(payload):
    """Retrieves the current region from the subcloud being migrated

    param: payload = Subcloud payload
    returns the OS_REGION_NAME param value from subcloud and error cause if
    occurs
    """
    bootstrap_addr = None
    bootstrap_pwd = None
    subcloud_region = None
    err_cause = None

    if not payload:
        err_cause = "Unable to get subcloud connection data: payload is empty"
        return (subcloud_region, err_cause)

    try:
        bootstrap_addr = payload.get("bootstrap-address")
        bootstrap_pwd = payload.get("sysadmin_password")

        if not bootstrap_addr:
            err_cause = (
                "Unable to get subcloud connection data: missing bootstrap-address"
            )
            return (subcloud_region, err_cause)

        if not bootstrap_pwd:
            err_cause = (
                "Unable to get subcloud connection data: missing sysadmin_password"
            )
            return (subcloud_region, err_cause)

        ip_address = netaddr.IPAddress(bootstrap_addr)

        if ip_address.version not in [4, 6]:
            err_cause = "Invalid subcloud bootstrap address"
            return (subcloud_region, err_cause)

        cmd = [
            "sshpass",
            "-p",
            str(bootstrap_pwd),
            "ssh",
            "-q",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "sysadmin@" + str(bootstrap_addr),
            REGION_VALUE_CMD,
        ]

        task = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
        if len(task) < 1:
            err_cause = "Malformed subcloud region"
            return subcloud_region, err_cause
        subcloud_region = str(task.split("=")[1]).strip()
    except Exception as e:
        # check_output() will raise CalledProcessError if the called
        # process returns a non-zero return code.
        # We are printing the exception name to avoid any sensitive
        # connection data
        err_cause = "exception %s occurred" % type(e).__name__
        subcloud_region = None

    system_regions = [
        dccommon_consts.DEFAULT_REGION_NAME,
        dccommon_consts.SYSTEM_CONTROLLER_NAME,
    ]

    if subcloud_region in system_regions:
        err_cause = "region %s is not valid for a subcloud" % subcloud_region
        subcloud_region = None

    if err_cause:
        LOG.error(err_cause)

    # Returns
    #   subcloud_region value if subcloud is reachable, otherwise None
    #   err_cause message if an exception occurs, otherwise None
    # For old systems the region value is the same as subcloud name:
    #   export OS_REGION_NAME=[human readable based region value]
    # For new systems the region is uuid format based:
    #   export OS_REGION_NAME=[uuid based region value]
    return (subcloud_region, err_cause)


@retry(
    retry_on_exception=lambda x: isinstance(x, exceptions.ServiceUnavailable),
    wait_exponential_multiplier=1000,  # Start with 1 second
    wait_exponential_max=10000,  # Cap at 10 seconds
    stop_max_attempt_number=60,  # Stop after 60 attempts
)
def get_region_name(
    endpoint, timeout=dccommon_consts.SYSINV_CLIENT_REST_DEFAULT_TIMEOUT
):
    url = endpoint + "/v1/isystems/region_id"
    response = requests.get(url, timeout=timeout)

    if response.status_code == 200:
        data = response.json()
        if "region_name" not in data:
            raise exceptions.NotFound

        region_name = data["region_name"]
        return region_name
    else:
        msg = f"GET region_name from {url} FAILED WITH RC {response.status_code}"
        LOG.error(msg)
        raise exceptions.ServiceUnavailable


def find_ansible_error_msg(subcloud_name, log_file, stage=None):
    """Find errors into ansible logs.

    It will search into ansible log for a fatal error expression.

    If fatal error is found, it will capture the message
    until the final expression. It will get always the more recent
    fatal error from the log files.
    If the error message is longer than N lines, it will be summarized.
    Also, the last task is provided.

    Returns the error message found
    Returns generic error message if not found or there is failures
    during search
    """

    error_found = False
    error_msg = []
    failed_task = ""

    cmd_1 = "awk"
    # awk command to get the information inside the last match found
    # starting with 'fatal: [' and ending with 'PLAY RECAP'.
    cmd_2 = r"""BEGIN {f=""}                  # initialize f
        /fatal: \[|ERROR/,/PLAY RECAP/ {      # capture text between two delimiters
            if ($0 ~ /fatal: \[|ERROR/) f=""  # reset f on a new match
            if ($0 ~ /PLAY RECAP/) next       # exclude last delimiter
            if ($0 == "") next                # exclude blank line
            f = f ? (f "\n" $0) : $0}         # assign or append to f
            END {print f}
            """
    try:
        # necessary check since is possible to have
        # the error in rotated ansible log
        files_for_search = add_latest_rotated_file(log_file)

        if len(files_for_search) < 2:
            cmd_list = [cmd_1, cmd_2, files_for_search[0]]
        else:
            cmd_list = [cmd_1, cmd_2, files_for_search[0], files_for_search[1]]

        error_msg_raw = subprocess.check_output(
            cmd_list, stderr=subprocess.STDOUT
        ).decode("utf-8")
        if len(error_msg_raw) > 1:
            error_found = True
            error_msg = [elem for elem in error_msg_raw.split("\n") if elem]
            failed_task = get_failed_task(files_for_search)
    except Exception as exc:
        LOG.error("Failed getting info from ansible log file :%s" % exc)

    if error_found and (len(error_msg) > MAX_LINES_MSG):
        error_msg = summarize_message(error_msg)
    error_msg = "\n".join(str(element) for element in error_msg)
    error_msg = error_msg.replace("'", '"')

    if error_found:
        msg = "FAILED %s playbook of (%s).\ndetail: %s \nFAILED TASK: %s" % (
            stage,
            subcloud_name,
            error_msg,
            failed_task,
        )
    else:
        msg = (
            "FAILED %s playbook of (%s).\ncheck individual log at "
            "%s for detailed output"
        ) % (stage, subcloud_name, log_file)

    return msg


def add_latest_rotated_file(log_file):
    """Find the latest rotated file for the given log file.

    Check the existence of the given log file with its latest rotated file.

    Returns the log file itself if it exists and the latest rotated file
    doesn't exist;
    or the log file and its latest rotated file if both exist;
    or the latest rotated file only if it exists but the log file itself
    doesn't exit.

    Raises exception if both of the log file and its latest rotated file
    don't exist.
    """

    log_files = []

    # the latest rotated log file
    log_file_temp = log_file + ".1"
    if os.path.exists(log_file_temp):
        log_files.append(log_file_temp)

    if os.path.exists(log_file):
        log_files.append(log_file)

    if len(log_files) == 0:
        raise Exception(
            "Log file %s and its latest rotated file don't exist." % log_file
        )

    return log_files


def get_failed_task(files):
    """Get last task failed

    It receives an ansible log file (or a couple of files)
    and search for the last failed task with its date

    Returns a string with the task and date
    """
    cmd_1 = "awk"
    # awk command to get the information about last failed task.
    # Match expression starting with 'TASK [' and ending with
    # 'fatal: ['
    cmd_2 = r"""BEGIN {f=""}            # initialize f
        /TASK \[/ {f=""}                # reset f on first match
        /TASK \[/,/fatal: \[/ {         # capture text between two delimiters
            if ($0 ~ /fatal: \[/) next  # exclude last delimiter
            if ($0 == "") next          # exclude blank line
            f = f ? (f "\n" $0) : $0}  # assign or append to f
            END {print f}
            """
    # necessary check since is possible to have
    # the error in rotated ansible log
    if len(files) < 2:
        awk_cmd = [cmd_1, cmd_2, files[0]]
    else:
        awk_cmd = [cmd_1, cmd_2, files[0], files[1]]

    try:
        failed_task = subprocess.check_output(awk_cmd, stderr=subprocess.STDOUT).decode(
            "utf-8"
        )
        if len(failed_task) < 1:
            return None
    except Exception as exc:
        LOG.error("Failed getting failed task :%s" % exc)
        return None
    failed_task = failed_task.replace("*", "")
    failed_task = failed_task.replace("'", '"')
    failed_task = [elem for elem in failed_task.split("\n") if elem]
    failed_task = "%s %s" % (failed_task[0], failed_task[1])
    return failed_task


def summarize_message(error_msg):
    """Summarize message.

    This function receives a long error message and
    greps it using key words to return a summarized
    error message.

    Returns a brief message.
    """
    list_of_strings_to_search_for = ["msg:", "fail", "error", "cmd", "stderr"]
    brief_message = []
    for line in error_msg:
        for s in list_of_strings_to_search_for:
            if re.search(s, line, re.IGNORECASE):
                if len(brief_message) >= MAX_LINES_MSG:
                    break
                # append avoiding duplicated items
                if line not in brief_message:
                    brief_message.append(line)
    return brief_message


def is_valid_for_backup_operation(operation, subcloud, bootstrap_address_dict=None):

    if operation == "create":
        return _is_valid_for_backup_create(subcloud)
    elif operation == "delete":
        return _is_valid_for_backup_delete(subcloud)
    elif operation == "restore":
        return _is_valid_for_backup_restore(subcloud, bootstrap_address_dict)
    else:
        msg = "Invalid operation %s" % operation
        LOG.error(msg)
        raise exceptions.ValidateFail(msg)


def _is_valid_for_backup_create(subcloud):
    if (
        subcloud.availability_status != dccommon_consts.AVAILABILITY_ONLINE
        or subcloud.management_state != dccommon_consts.MANAGEMENT_MANAGED
        or subcloud.deploy_status != consts.DEPLOY_STATE_DONE
        or subcloud.prestage_status in consts.STATES_FOR_ONGOING_PRESTAGE
    ):
        msg = (
            "Subcloud %s must be deployed, online, managed, and no ongoing prestage "
            "for the subcloud-backup create operation." % subcloud.name
        )
        raise exceptions.ValidateFail(msg)

    return True


def _is_valid_for_backup_delete(subcloud):
    if (
        subcloud.availability_status != dccommon_consts.AVAILABILITY_ONLINE
        or subcloud.management_state != dccommon_consts.MANAGEMENT_MANAGED
    ):
        msg = (
            "Subcloud %s must be online and managed for the subcloud-backup "
            "delete operation with --local-only option." % subcloud.name
        )
        raise exceptions.ValidateFail(msg)

    return True


def _is_valid_for_backup_restore(subcloud, bootstrap_address_dict=None):

    msg = None
    ansible_subcloud_inventory_file = get_ansible_filename(
        subcloud.name, consts.INVENTORY_FILE_POSTFIX
    )
    has_bootstrap_address = (
        bootstrap_address_dict and subcloud.name in bootstrap_address_dict
    )
    has_install_values = subcloud.data_install is not None
    has_inventory_file = os.path.exists(ansible_subcloud_inventory_file)

    if (
        subcloud.management_state != dccommon_consts.MANAGEMENT_UNMANAGED
        or subcloud.deploy_status in consts.INVALID_DEPLOY_STATES_FOR_RESTORE
    ):
        msg = (
            "Subcloud %s must be unmanaged and in a valid deploy state "
            "for the subcloud-backup restore operation." % subcloud.name
        )
    elif not (has_bootstrap_address or has_install_values or has_inventory_file):
        msg = (
            "Unable to obtain the subcloud %s bootstrap_address from either "
            "restore or install values. Please ensure bootstrap_address is "
            "specified in the restore-values.yml and try again." % subcloud.name
        )
    elif has_bootstrap_address:
        try:
            netaddr.IPAddress(bootstrap_address_dict[subcloud.name])
        except netaddr.AddrFormatError:
            msg = (
                f"Subcloud {subcloud.name} must have a valid bootstrap address: "
                f"{bootstrap_address_dict[subcloud.name]}"
            )
    if msg:
        raise exceptions.ValidateFail(msg)

    return True


def get_matching_iso(software_version=None):
    try:
        if not software_version:
            software_version = tsc.SW_VERSION
        matching_iso, _ = get_vault_load_files(software_version)
        if not matching_iso:
            error_msg = (
                f"Failed to get {software_version} load image. Provide active/inactive "
                "load image via 'software --os-region-name SystemController upload'"
            )
            LOG.exception(error_msg)
            return None, error_msg
        return matching_iso, None
    except Exception as e:
        LOG.exception("Could not load vault files.")
        return None, str(e)


def is_subcloud_healthy(subcloud_region, management_ip: str = None):

    system_health = ""
    try:
        os_client = OpenStackDriver(
            region_name=subcloud_region,
            region_clients=None,
            fetch_subcloud_ips=fetch_subcloud_mgmt_ips,
            subcloud_management_ip=management_ip,
        )
        keystone_client = os_client.keystone_client
        endpoint = keystone_client.endpoint_cache.get_endpoint("sysinv")
        sysinv_client = SysinvClient(
            subcloud_region, keystone_client.session, endpoint=endpoint
        )
        system_health = sysinv_client.get_system_health()
    except Exception as e:
        LOG.exception(e)
        raise

    fails = re.findall(r"\[Fail\]", system_health)
    failed_alarm_check = re.findall(r"No alarms: \[Fail\]", system_health)
    no_mgmt_alarms = re.findall(
        r"\[0\] of which are management affecting", system_health
    )

    # Subcloud is considered healthy if there are no failures or
    # a single failure with only low severity alarms (not management affecting)
    if (len(fails) == 0) or (len(fails) == 1 and failed_alarm_check and no_mgmt_alarms):
        return True

    LOG.error(
        f"Subcloud {subcloud_region} failed health check. Health output: "
        f"\n{system_health}\n"
    )
    return False


def get_system_controller_software_list(
    region_name=dccommon_consts.DEFAULT_REGION_NAME,
):
    """Get software list from USM API

    This function is responsible for querying the USM API for the list of releases
    present on the node through the USM endpoint.

    The node is determined from the parameter region_name, whose default value
    represents the region one.

    Args:
        region_name (str): The name of the region to be consulted. Default is
        RegionOne.

    Returns:
        list of dict: each dict item contains the parameters that identify
        the release from API response
    """
    try:
        os_client = OpenStackDriver(
            region_name=region_name,
            region_clients=None,
            fetch_subcloud_ips=fetch_subcloud_mgmt_ips,
        )
        ks_client = os_client.keystone_client
        software_client = software_v1.SoftwareClient(
            ks_client.session,
            endpoint=ks_client.endpoint_cache.get_endpoint("usm"),
        )
        return software_client.list()

    except (requests.exceptions.ConnectionError, keystone_exceptions.ConnectionError):
        LOG.exception("Failed to get software list for %s", region_name)
        raise
    except Exception:
        LOG.exception("Failed to get keystone client for %s", region_name)
        raise


def get_systemcontroller_deployed_releases(
    software_list: List[dict], key: str = "sw_version"
) -> List[str]:
    """Get a list of deployed software releases on the SystemController using the key.

    This function is used to get the deployed software releases on the SystemController
    using the key provided. For example, the key can be "sw_version" or "release_id",
    this will return ["10.0.0", "10.0.2", ...] or ["stx-10.0.0", "stx-10.0.1", ...]
    respectively. Other keys can be used as well, like "state", "description", etc.

    Args:
        software_list (list): The software list provided by USM API
        key (str): (default 'sw_version') The key to extract information from each
        deployed release.

    Returns:
        List[str]: Values of the given key from all deployed software releases.

    """
    deployed_releases = [
        release[key]
        for release in software_list
        if release["state"] == software_v1.DEPLOYED
    ]

    return deployed_releases


def get_systemcontroller_installed_releases_ids() -> List[str]:
    software_list = get_system_controller_software_list()
    return get_systemcontroller_deployed_releases(software_list, key="release_id")


def is_software_ready_to_be_prestaged_for_install(software_list, software_version):
    """Check if software is ready to be prestaged for install

    This function checks if a given release version is ready to be deployed.
    The criteria to consult is valid when a prestage is performed from the
    for_install parameter, since for for_sw_deploy this is not required.

    To determine if the release is valid for install, it is initially compared
    to the release of the system controller. If matches, it is assumed that the
    release is already deployed and it is not required to check the
    software list. Otherwise, the query will be made in the list of software
    for the available status, since those releases that have not yet been
    deployed must be considered.

    Args:
        software_list (list[dict]): The software list from USM API
        software_version (str): The requested software version

    Returns:
        bool: `True` if software version matches, otherwise `False`

    """
    # It is assumed that if the requested release matches the release deployed
    # on the system controller, checking against the software list is not required.
    if software_version == tsc.SW_VERSION:
        return True

    # It is necessary to query the list for the requested release,
    # whose status must be available, unavailable or deployed to be
    # able to install it
    return any(
        is_base_release(release["sw_version"])
        and get_major_release(release["sw_version"]) == software_version
        and release["state"]
        in (software_v1.AVAILABLE, software_v1.DEPLOYED, software_v1.UNAVAILABLE)
        for release in software_list
    )


def get_prestage_reason(payload):
    """Get the prestage reason from payload

    This function is used to get the prestage reason from payload checking the
    for_sw_deploy param.

    Args:
        payload (dict): payload from request

    Returns:
        str: for_sw_deploy if param is present on payload
        str: for_install if param is absent (default)

    """
    if payload.get(consts.PRESTAGE_FOR_SW_DEPLOY):
        return consts.PRESTAGE_FOR_SW_DEPLOY

    return consts.PRESTAGE_FOR_INSTALL


def get_validated_sw_version_for_prestage(payload, subcloud=None):
    """Get the validated software version from payload

    This function is used to get the software version previously being validated
    to determine if the value is correct, that is, if it meets the requirements
    to be considered a valid release.

    It is validated if the release format meets the expected format (MM.mm).

        Where MM is the high part of the release, for example: 24.
        Where mm is the lower part of the release, for example: 09.

    Any value that does not respect the format is considered an invalid release,
    including formats such as: 24.09.1, 24.09.1.1, alphabetical characters and
    symbols.

    It is expected to receive only numbers that represent a valid release separated
    by "."; i.e: 22.12, 24.09.

    Args:
        payload (dict): payload from request
        subcloud (dict): subcloud params if present

    Returns:
        tuple: The release validation result:
            - str: The first item represents the validated release, that is, the
            value of the release that was requested. If a validation error occurs,
            the value will be None.
            - str: The second element represents a message in case of error.

    """
    for_sw_deploy = get_prestage_reason(payload) == consts.PRESTAGE_FOR_SW_DEPLOY
    for_install = not for_sw_deploy
    software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE)
    subcloud = {} if subcloud is None else subcloud

    # If the release parameter is present in the payload, it validates if
    # the format is MM.mm. Otherwise it will return error.
    if software_version and not is_major_release(software_version):
        return None, (
            "Specified release format is not supported. Version format "
            "must be MM.mm."
        )

    # Gets the release in validated MM.mm format.
    software_version = get_sw_version(software_version, for_install)

    # Query to the USM API to get the software list
    software_list = get_system_controller_software_list()

    # Gets only the list of deployed major releases.
    deployed_releases = get_major_releases(
        get_systemcontroller_deployed_releases(software_list)
    )

    # Check for deploy release param
    if for_sw_deploy:
        # 22.12 version is not supported for software deploy
        if software_version < consts.SOFTWARE_VERSION_24_09:
            return None, (
                "The requested software version is not supported, "
                "cannot prestage for software deploy."
            )

        # Ensures that the requested release version exists within the
        # list of deployed releases
        if software_version not in deployed_releases:
            return None, (
                "The requested software version was not installed in the "
                "system controller, cannot prestage for software deploy."
            )

        # If there is only one deployed release, it implies that it corresponds
        # to the base release. Therefore, prestage is not required.
        if len(software_list) == 1:
            return None, (
                "Only base release is deployed, cannot prestage for software deploy."
            )

        # We want to check if the USM API is available on the subcloud. This allows us
        # to determine if the prestage should be run for N-1 subcloud.
        if subcloud and subcloud.software_version < consts.SOFTWARE_VERSION_24_09:
            LOG.info(
                f"Checking USM service availability for {subcloud.name} with software "
                f"version: {subcloud.software_version}"
            )
            try:
                if not has_usm_service(subcloud.region_name):
                    return None, (
                        "USM service not found for subcloud, cannot prestage for "
                        "software deploy."
                    )
            except exceptions.InternalError:
                return None, (
                    "Unable to check USM service for subcloud, cannot prestage "
                    "for software deploy."
                )

    else:
        # Check for install release param
        if not is_software_ready_to_be_prestaged_for_install(
            software_list, software_version
        ):
            return None, ("The requested release is not ready to be installed.")

    return software_version, ""


def get_certificate_from_secret(secret_name, secret_ns):
    """Get certificate from k8s secret

    :param secret_name: the name of the secret
    :param secret_ns: the namespace of the secret

    :return: tls_crt: the certificate.
             tls_key: the corresponding private key of the certificate.
             ca_crt: the CA certificate that issued tls_crt if available.
    raise Exception for kubernetes data errors
    """

    kube = kubeoperator.KubeOperator()
    secret = kube.kube_get_secret(secret_name, secret_ns)

    if not hasattr(secret, "data"):
        raise Exception("Invalid secret %s\\%s" % (secret_ns, secret_name))

    data = secret.data
    if "tls.crt" not in data or "tls.key" not in data:
        raise Exception(
            "Invalid certificate data from secret %s\\%s" % (secret_ns, secret_name)
        )

    try:
        tls_crt = base64.decode_as_text(data["tls.crt"])
        tls_key = base64.decode_as_text(data["tls.key"])
        if "ca.crt" in data:
            ca_crt = base64.decode_as_text(data["ca.crt"])
        else:
            LOG.warning(
                "Secret doesn't have required CA data stored:  %s\\%s"
                % (secret_ns, secret_name)
            )
            ca_crt = ""
    except TypeError:
        raise Exception(
            "Certificate secret data is invalid %s\\%s" % (secret_ns, secret_name)
        )

    return tls_crt, tls_key, ca_crt


def get_management_subnet(payload):
    """Get management subnet.

    Given a payload dict, prefer an admin
    subnet over a management subnet if it
    is present.

    Returns the management subnet.
    """
    if payload.get("admin_subnet", None):
        return payload.get("admin_subnet")
    return payload.get("management_subnet", "")


def get_primary_management_subnet(payload):
    """Get primary management subnet.

    Returns the primary management subnet.
    """
    return get_management_subnet(payload).split(",")[0]


def get_management_start_address(payload):
    """Get management start address.

    Given a payload dict, prefer an admin
    start address over a management start address
    if it is present.

    Returns the management start address.
    """
    if payload.get("admin_start_address", None):
        return payload.get("admin_start_address")
    return payload.get("management_start_address", "")


def get_primary_management_start_address(payload):
    """Get primary management start address.

    Returns the primary management start address.
    """
    return get_management_start_address(payload).split(",")[0]


def get_management_end_address(payload):
    """Get management end address.

    Given a payload dict, prefer an admin
    end address over a management end address
    if it is present.

    Returns the management end address.
    """
    if payload.get("admin_end_address", None):
        return payload.get("admin_end_address")
    return payload.get("management_end_address", "")


def get_primary_management_end_address(payload):
    """Get primary management end address.

    Returns the primary management end address.
    """
    return get_management_end_address(payload).split(",")[0]


def get_primary_management_gateway_address(payload):
    """Get primary management gateway address.

    Given a payload dict, prefer an admin
    gateway address over a management gateway address
    if it is present.

    Returns the primary management gateway address.
    """
    if payload.get("admin_gateway_address", None):
        return payload.get("admin_gateway_address").split(",")[0]
    return payload.get("management_gateway_address", "").split(",")[0]


def get_primary_systemcontroller_gateway_address(payload):
    """Get primary systemcontroller gateway address.

    Returns the primary systemcontroller gateway address.
    """
    if payload.get("systemcontroller_gateway_address", None):
        return payload.get("systemcontroller_gateway_address").split(",")[0]
    return None


def get_primary_management_gateway_address_ip_family(payload):
    """Get primary management gateway address family"""
    address_value = get_primary_management_gateway_address(payload)
    try:
        ip_address = netaddr.IPAddress(address_value)
    except Exception as e:
        raise exceptions.ValidateFail(f"Invalid address - not a valid IP address: {e}")
    return ip_address.version


def get_primary_oam_address_ip_family(payload):
    """Get primary oam address's IP family

    :param payload: subcloud configuration
    """
    # First check external_oam_subnet_ip_family, if it is
    # DB subcloud payload
    if payload.get("external_oam_subnet_ip_family", None):
        try:
            family = int(payload.get("external_oam_subnet_ip_family"))
            if family == 4 or family == 6:
                return family
            raise exceptions.ValidateFail(
                f"Invalid external_oam_subnet_ip_family: {family}"
            )
        except Exception as e:
            raise exceptions.ValidateFail(f"Invalid external_oam_subnet_ip_family: {e}")

    network_value = payload.get("external_oam_subnet", "").split(",")[0]
    try:
        ip_network = netaddr.IPNetwork(network_value)
    except Exception as e:
        raise exceptions.ValidateFail(
            f"Invalid OAM network - not a valid IP Network: {e}"
        )
    return ip_network.version


def has_network_reconfig(payload, subcloud):
    """Check if network reconfiguration is needed

    :param payload: subcloud configuration
    :param subcloud: subcloud object
    """
    management_subnet = get_primary_management_subnet(payload)
    start_address = get_primary_management_start_address(payload)
    end_address = get_primary_management_end_address(payload)
    gateway_address = get_primary_management_gateway_address(payload)
    sys_controller_gw_ip = get_primary_systemcontroller_gateway_address(payload)

    has_network_reconfig = any(
        [
            management_subnet != subcloud.management_subnet,
            start_address != subcloud.management_start_ip,
            end_address != subcloud.management_end_ip,
            gateway_address != subcloud.management_gateway_ip,
            sys_controller_gw_ip != subcloud.systemcontroller_gateway_ip,
        ]
    )

    return has_network_reconfig


def set_open_file_limit(new_soft_limit: int):
    """Adjust the maximum number of open files for this process (soft limit)"""
    try:
        current_soft, current_hard = sys_resource.getrlimit(sys_resource.RLIMIT_NOFILE)
        if new_soft_limit > current_hard:
            LOG.error(
                f"New process open file soft limit [{new_soft_limit}] exceeds the "
                f"hard limit [{current_hard}]. Setting to hard limit instead."
            )
            new_soft_limit = current_hard
        if new_soft_limit != current_soft:
            LOG.info(
                f"Setting process open file limit to {new_soft_limit} "
                f"(from {current_soft})"
            )
            sys_resource.setrlimit(
                sys_resource.RLIMIT_NOFILE, (new_soft_limit, current_hard)
            )
    except Exception as ex:
        LOG.exception(f"Failed to set NOFILE resource limit: {ex}")


def get_playbook_for_software_version(playbook_filename, software_version=None):
    """Get the ansible playbook filename in corresponding software version.

    :param playbook_filename: ansible playbook filename
    :param software_version: software version
    :raises PlaybookNotFound: If the playbook is not found

    Returns the unchanged ansible playbook filename if the software version
    parameter is not provided or the same as active release, otherwise, returns
    the filename in corresponding software version.
    """
    if software_version and software_version != tsc.SW_VERSION:
        software_version_path = os.path.join(
            consts.ANSIBLE_PREVIOUS_VERSION_BASE_PATH, software_version
        )
        playbook_filename = playbook_filename.replace(
            consts.ANSIBLE_CURRENT_VERSION_BASE_PATH, software_version_path
        )
    if not os.path.isfile(playbook_filename):
        raise exceptions.PlaybookNotFound(playbook_name=playbook_filename)
    return playbook_filename


def get_value_from_yaml_file(filename, key):
    """Get corresponding value for a key in the given yaml file.

    :param filename: the yaml filename
    :param key: the path for the value

    Returns the value or None if not found.
    """
    value = None
    if os.path.isfile(filename):
        with open(os.path.abspath(filename), "r") as f:
            data = f.read()
        data = yaml.load(data, Loader=yaml.SafeLoader)
        value = data.get(key)
    return value


def update_values_on_yaml_file(filename, values, values_to_keep=None, yaml_dump=True):
    """Update all specified key values from the given yaml file.

    If values_to_keep is provided, all values other than specified
    will be deleted from the loaded file prior to update.

    :param filename: the yaml filename
    :param values: dict with yaml keys and values to replace
    :param values_to_keep: list of values to keep on original file
    :param yaml_dump: write file using yaml dump (default is True)

    returns True if the yaml file exists else False
    """
    if values_to_keep is None:
        values_to_keep = []
    update_file = False
    if not os.path.isfile(filename):
        return False
    with open(os.path.abspath(filename), "r") as f:
        data = f.read()
    data = yaml.load(data, Loader=yaml.SafeLoader)
    if values_to_keep:
        for key in data.copy():
            if key not in values_to_keep:
                data.pop(key)
                update_file = True
    for key, value in values.items():
        if key not in data or value != data.get(key):
            data.update({key: value})
            update_file = True
    if update_file:
        with open(os.path.abspath(filename), "w") as f:
            if yaml_dump:
                yaml.dump(data, f, sort_keys=False)
            else:
                f.write("---\n")
                for k, v in data.items():
                    f.write("%s: %s\n" % (k, json.dumps(v)))
    return True


def load_yaml_file(filename: str):
    with open(os.path.abspath(filename), "r") as f:
        data = yaml.load(f, Loader=yaml.loader.SafeLoader)
    return data


def update_install_values_with_new_bootstrap_address(context, payload, subcloud):
    """Update install values with new bootstrap address provided on request

    This is necessary during deploy bootstrap if the user provided a new
    bootstrap_address, so future redeploy/upgrade is not affected

    :param context: request context object
    :param payload: subcloud payload
    :param subcloud: subcloud object
    """

    if not subcloud.data_install:
        return
    bootstrap_address = payload.get(consts.BOOTSTRAP_ADDRESS)
    install_values = json.loads(subcloud.data_install)
    if bootstrap_address and bootstrap_address != install_values.get(
        "bootstrap_address"
    ):
        install_values["bootstrap_address"] = bootstrap_address
        db_api.subcloud_update(
            context, subcloud.id, data_install=json.dumps(install_values)
        )


def decode_and_normalize_passwd(input_passwd):
    pattern = r"^[" + string.punctuation + "]"
    passwd = base64.decode_as_text(input_passwd)
    # Ensure that sysadmin password which starts with a special
    # character will be enclosed in quotes so that the generated
    # inventory file will be parsable by Ansible.
    if not passwd.startswith('"') and re.search(pattern, passwd):
        passwd = '"' + passwd + '"'
    elif passwd.startswith('"') and not passwd.endswith('"'):
        passwd = "'" + passwd + "'"

    return passwd


def update_abort_status(context, subcloud_id, deploy_status, abort_failed=False):
    """Update the subcloud deploy status during deploy abort operation.

    :param context: request context object
    :param subcloud_id: subcloud id from db
    :param deploy_status: subcloud deploy status from db
    :param abort_failed: if abort process fails (default False)
    """
    if abort_failed:
        abort_status_dict = ABORT_UPDATE_FAIL_STATUS
    else:
        abort_status_dict = ABORT_UPDATE_STATUS
    new_deploy_status = abort_status_dict[deploy_status]
    updated_subcloud = db_api.subcloud_update(
        context, subcloud_id, deploy_status=new_deploy_status
    )
    return updated_subcloud


def subcloud_is_secondary_state(deploy_state):
    if deploy_state in [
        consts.DEPLOY_STATE_SECONDARY,
        consts.DEPLOY_STATE_SECONDARY_FAILED,
    ]:
        return True
    return False


def create_subcloud_rehome_data_template():
    """Create a subcloud rehome data template"""
    return {"saved_payload": {}}


def get_sw_version(release=None, for_install=True):
    """Get the sw_version to be used.

    Return the sw_version by first validating a set release version.
    If a release is not specified then use the current system controller
    software_version.

    for_install = True (--for-install) then it will validate the
    requested release against the upgrade support file.

    for_install = False (--for-sw-deploy) then it will return the
    requested release in format MM.mm previously validated.

    """

    if release:
        try:
            if for_install:
                validate_major_release_version_supported(release)
            else:
                release = get_major_release(release)
            return release
        except exceptions.ValidateFail as e:
            pecan.abort(400, _("Error: invalid release version parameter. %s" % e))
        except Exception:
            pecan.abort(500, _("Error: unable to validate the release version."))
    else:
        return tsc.SW_VERSION


def validate_major_release_version_supported(release_version_to_check):
    """Check if a release version is supported by the current active version.

    :param release_version_to_check: version string to validate

    returns True to indicate that the version is valid
    raise ValidateFail for an invalid/unsupported release version
    """

    current_version = tsc.SW_VERSION

    if current_version == release_version_to_check:
        return True

    supported_versions = get_current_supported_upgrade_versions()

    if release_version_to_check not in supported_versions:
        msg = "%s is not a supported release version (%s)" % (
            release_version_to_check,
            ",".join(supported_versions),
        )
        raise exceptions.ValidateFail(msg)

    return True


def is_major_release(version):
    """Check if a given version is a valid major release

    This function is useful for determining whether a given version
    represents a major release.

    Both the MM part and the mm part must have two digits.

    Args:
        version (str): The requested version value

    Returns:
        bool: `True` if the version value meets the expected format.
        `False` if the version format is not valid.

    """
    pattern = r"^\d{2}\.\d{2}$"
    if not re.match(pattern, version):
        return False

    MM, mm = version.split(".")
    MM = int(MM)
    mm = int(mm)
    return 0 <= MM <= 99 and 0 <= mm <= 99


def is_minor_release(version):
    """Check if a given version is a valid minor release

    The third value in a release format representation,
    for example MM.mm.pp, is considered a minor release.

    Both the MM part and the mm part must have two digits.
    The pp part can have one digit or two.

    The third part of the format starting from 1 is considered a minor
    release, since 0 represents the major release.

    Args:
        version (str): The requested version value

    Returns:
        bool: `True` if the version value meets the expected format.
        `False` if the version format is not valid.

    """
    pattern = r"^\d{2}\.\d{2}\.\d{1,2}$"
    if not re.match(pattern, version):
        return False

    MM, mm, pp = version.split(".")
    MM = int(MM)
    mm = int(mm)
    pp = int(pp)
    return 0 <= MM <= 99 and 0 <= mm <= 99 and 1 <= pp <= 99


def is_base_release(version):
    """Check if a given version is a valid base release

    The third value in a release format representation,
    for example MM.mm.p, is considered a base release.

    Both the MM part and the mm part must have two digits.
    The p part represents the base release digit, which is always 0.

    Args:
        version (str): The requested version value

    Returns:
        bool: `True` if the version value is a valid base release.
        `False` if the version is a not valid base release.

    """

    if version < consts.SOFTWARE_VERSION_24_09:
        return is_major_release(version)

    pattern = r"^\d{2}\.\d{2}\.\d{1}$"
    if not re.match(pattern, version):
        return False

    MM, mm, p = version.split(".")
    MM = int(MM)
    mm = int(mm)
    p = int(p)
    return 0 <= MM <= 99 and 0 <= mm <= 99 and 0 == p


def extract_version(release_id: str) -> str:
    """Extract the MM.mm part of a release_id.

    Args:
        release_id: The release_id. Example: stx-10.0.1

    Returns:
        str: The extracted major.minor version in the format MM.mm, or
             None if not found.
    """
    # Regular expression to match the MM.mm part of the version
    pattern = r"(\d{1,2}\.\d{1,2})"

    # Search for the MM.mm pattern in the version_string
    match = re.search(pattern, release_id)

    # Return the MM.mm part if found, otherwise return None
    if match:
        return match.group(1)
    return None


def get_major_release(version):
    """Returns the YY.MM portion of the given version string"""
    split_version = version.split(".")
    return ".".join(split_version[0:2])


def get_current_supported_upgrade_versions():
    """Parse the upgrades metadata file to build a list of supported versions.

    returns a list of supported upgrade versions
    raise InternalError exception for a missing/invalid metadata file
    """

    supported_versions = []

    try:
        with open(consts.SUPPORTED_UPGRADES_METADATA_FILE_PATH) as file:
            root = ElementTree.fromstring(file.read())
    except Exception:
        LOG.exception("Error reading the supported upgrades metadata file")
        raise exceptions.InternalError()

    supported_upgrades = root.find("supported_upgrades")

    if not supported_upgrades:
        LOG.error("Missing supported upgrades information")
        raise exceptions.InternalError()

    upgrades = supported_upgrades.findall("upgrade")

    for upgrade in upgrades:
        version = upgrade.findtext("version")
        supported_versions.append(version.strip())

    return supported_versions


def get_major_releases(releases):
    """Returns release list in format MM.mm"""
    major_releases = []

    for release in releases:
        major_release = get_major_release(release)
        if major_release not in major_releases:
            major_releases.append(major_release)

    return major_releases


# Feature: Subcloud Name Reconfiguration
# This method is useful to determine the origin of the request
# towards the api. The goal was to avoid any code changes in
# the cert-monitor module, since it only needs the region reference.
# When this method is called, the condition is applied to replace the
# value of the "name" field with the value of the "region_name" field
# in the response. In this way, the cert-monitor does not lose the
# region reference in subcloud rename operation.
def is_req_from_cert_mon_agent(request):
    ua = request.headers.get("User-Agent")
    if ua == consts.CERT_MON_HTTP_AGENT:
        return True
    else:
        return False


def yaml_safe_load(contents, content_type):
    """Wrapper for yaml.safe_load with error logging and reporting.

    :param contents: decoded contents to load
    :param content_type: values being loaded
    :returns dict constructed from parsed contents
    """
    error = False
    msg = "Error: Unable to load " + content_type + " file contents ({})."

    try:
        data = yaml.safe_load(contents)
        if data is None:
            error = True
            msg = msg.format("empty file provided")
    except yaml.YAMLError as e:
        error = True
        if hasattr(e, "problem_mark"):
            mark = e.problem_mark
            msg = msg.format("problem on line: " + str(mark.line))
        else:
            msg = msg.format("please see logs for more details")

        LOG.exception(e)

    if error:
        LOG.error(msg)
        pecan.abort(400, _(msg))

    return data


# Feature: Subcloud Name Reconfiguration
# This method is useful to determine the origin of the request
# towards the api.
def is_req_from_another_dc(request):
    ua = request.headers.get("User-Agent")
    if ua == consts.DCMANAGER_V1_HTTP_AGENT:
        return True
    else:
        return False


def validate_name(
    name,
    prohibited_name_list=[],
    invalid_chars=".*+?|()[]{}^$",
    max_length=255,
    case_sensitive=False,
):
    """validate name string.

    :param name: name string
    :param prohibited_name_list: a list containing prohibited string
    :param max_length: max length of name
    :param invalid_chars: default is regular expression chars
    :param case_sensitive: case sensitive setting for prohibited_name_list
    :returns boolean value as result
    """
    special_chars = set(invalid_chars)
    if not name:
        return False
    if name.isdigit():
        LOG.warning("Invalid name [%s], can not be digit" % name)
        return False
    if len(name) > max_length:
        LOG.warning("Invalid name length")
        return False
    for char in name:
        if char in special_chars:
            LOG.warning(
                "Invalid name, Prohibited to use regular expression characters: %s"
                % name
            )
            return False

    normalized_name = name if case_sensitive else name.lower()
    normalized_prohibited_list = (
        prohibited_name_list
        if case_sensitive
        else [s.lower() for s in prohibited_name_list]
    )
    if normalized_name in normalized_prohibited_list:
        LOG.warning("Invalid name, cannot use '%s' as name" % name)
        return False
    return True


def get_local_system():
    m_ks_client = OpenStackDriver(
        region_name=dccommon_consts.DEFAULT_REGION_NAME,
        region_clients=None,
        fetch_subcloud_ips=fetch_subcloud_mgmt_ips,
    ).keystone_client
    endpoint = m_ks_client.endpoint_cache.get_endpoint("sysinv")
    sysinv_client = SysinvClient(
        dccommon_consts.DEFAULT_REGION_NAME, m_ks_client.session, endpoint=endpoint
    )
    system = sysinv_client.get_system()
    return system


def get_msg_output_info(log_file, target_task, target_str):
    """Get msg output by searching the target string from the given task.

    It receives an ansible log file and searches for the last msg output
    matching the target string from the given task.

    Returns the msg output
    """

    # awk command to get the last occurrence string after 'msg: {target_str}'
    # between 'TASK \[{target_task}' and 'PLAY RECAP' delimiters.
    awk_script = rf"""
    /TASK \[{target_task}/,/PLAY RECAP/ {{
        if ($0 ~ /msg: '{target_str}(.+)'/) {{
            result = $0
        }}
    }}
    END {{
        if (result) {{
            match(result, /msg: '{target_str}(.+)'/, arr)
            print arr[1]
        }}
    }}
    """
    try:
        # necessary check since is possible to have
        # the message in rotated ansible log
        files_for_search = add_latest_rotated_file(log_file)
        awk_cmd = ["awk", awk_script] + files_for_search
        # Run the AWK script using subprocess
        result = subprocess.run(awk_cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception as e:
        LOG.error(
            "Failed getting msg output by searching '%s' from task '%s': %s"
            % (target_str, target_task, e)
        )
        return None


def get_subcloud_ansible_log_file(subcloud_name):
    return os.path.join(
        consts.DC_ANSIBLE_LOG_DIR, subcloud_name + "_playbook_output.log"
    )


def is_leader_on_local_site(peer_group):
    return peer_group.system_leader_id == get_local_system().uuid


def generate_sync_info_message(association_ids):
    info_message = None
    if association_ids:
        info_message = (
            "The operation has caused the SPG to be out-of-sync. "
            "Please run peer-group-association sync command to push "
            "the subcloud peer group changes to the peer site:\n"
        )
        for association_id in association_ids:
            info_message += (
                f"$ dcmanager peer-group-association sync {association_id}\n"
            )
    return info_message


def fetch_subcloud_mgmt_ips(region_name: str = None) -> Union[dict, str]:
    """Fetch the subcloud(s) primary management IP(s).

    :param region_name: The subcloud region name, defaults to None
    :return: A dictionary of region names to IPs (if no region provided)
        or a single IP string (for specific region).
    """
    LOG.info(f"Fetching subcloud(s) management IP(s) ({region_name=})")
    ctx = context.get_admin_context()
    if region_name:
        subcloud = db_api.subcloud_get_by_region_name(ctx, region_name)
        return subcloud.management_start_ip

    ip_map = {}
    subclouds = db_api.subcloud_get_all(ctx)
    for subcloud in subclouds:
        ip_map[subcloud.region_name] = subcloud.management_start_ip
    return ip_map


def format_address(ip_address: str) -> str:
    """Formats an IP address for use in a URL.

    IPv6 addresses are enclosed in square brackets.
    """
    try:
        address = netaddr.IPAddress(ip_address)
        if address.version == 6:
            return f"[{address}]"
        return str(address)
    except netaddr.AddrFormatError as e:
        LOG.error(f"Failed to format the IP address: {ip_address}. Error: {e}")
        raise


def validate_patch_strategy(payload: dict):
    patch_id = payload.get("patch_id")
    if not patch_id:
        message = (
            "patch_id parameter is required for "
            f"{consts.SW_UPDATE_TYPE_PATCH} strategy."
        )
        pecan.abort(400, _(message))

    patch_file = (
        f"{consts.PATCH_VAULT_DIR}/{consts.PATCHING_SW_VERSION}/{patch_id}.patch"
    )
    if not os.path.isfile(patch_file):
        message = f"Patch file {patch_file} is missing in DC Vault patches."
        pecan.abort(400, _(message))

    remove = payload.get("remove", "").lower() == "true"
    upload_only = payload.get("upload-only", "").lower() == "true"

    if remove and upload_only:
        message = "Both remove and upload-only parameters cannot be used together."
        pecan.abort(400, _(message))


def validate_software_strategy(release_id: str):
    if not release_id:
        message = (
            "Release ID is required for strategy type: "
            f"{consts.SW_UPDATE_TYPE_SOFTWARE}."
        )
        pecan.abort(400, _(message))
    elif release_id not in get_systemcontroller_installed_releases_ids():
        message = f"Release ID: {release_id} not deployed in the SystemController"
        pecan.abort(400, _(message))


def has_usm_service(
    subcloud_region: str, keystone_client: KeystoneClient = None
) -> bool:

    # Lookup keystone client session if not specified
    if not keystone_client:
        try:
            keystone_client = OpenStackDriver(
                region_name=subcloud_region,
                region_clients=None,
                fetch_subcloud_ips=fetch_subcloud_mgmt_ips,
            ).keystone_client.keystone_client
        except Exception as e:
            LOG.exception(
                f"Failed to get keystone client for subcloud_region: {subcloud_region}"
            )
            raise exceptions.InternalError() from e
    try:
        # Try to get the USM service for the subcloud.
        keystone_client.services.find(name=dccommon_consts.ENDPOINT_NAME_USM)
        return True
    except keystone_exceptions.NotFound:
        LOG.warning("USM service not found for subcloud_region: %s", subcloud_region)
        return False


def get_system_controller_deploy() -> Optional[dict]:
    # get a cached keystone client (and token)
    try:
        os_client = OpenStackDriver(
            region_name=dccommon_consts.SYSTEM_CONTROLLER_NAME, region_clients=None
        )
    except Exception:
        LOG.exception(
            "Failed to get keystone client for %s",
            dccommon_consts.SYSTEM_CONTROLLER_NAME,
        )
        raise

    ks_client = os_client.keystone_client
    software_client = software_v1.SoftwareClient(
        ks_client.session,
        dccommon_consts.SYSTEM_CONTROLLER_NAME,
        endpoint=ks_client.endpoint_cache.get_endpoint(
            dccommon_consts.ENDPOINT_NAME_USM
        ),
    )
    # Show deploy always returns either an empty list when there's no deploy
    # or a list with a single element when there's a deploy
    deploy_list = software_client.show_deploy()
    return deploy_list[0] if deploy_list else None


def is_system_controller_deploying() -> bool:
    return get_system_controller_deploy() is not None
