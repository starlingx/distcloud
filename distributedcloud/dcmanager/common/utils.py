# Copyright 2015 Huawei Technologies Co., Ltd.
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

import grp
import itertools
import netaddr
import os
import pwd
import six.moves
import tsconfig.tsconfig as tsc

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.db import api as db_api
from dcorch.common import consts as dcorch_consts

LOG = logging.getLogger(__name__)

DC_MANAGER_USERNAME = "root"
DC_MANAGER_GRPNAME = "root"


def get_import_path(cls):
    return cls.__module__ + "." + cls.__name__


# Returns a iterator of tuples containing batch_size number of objects in each
def get_batch_projects(batch_size, project_list, fillvalue=None):
    args = [iter(project_list)] * batch_size
    return six.moves.zip_longest(fillvalue=fillvalue, *args)


def validate_address_str(ip_address_str, network):
    """Determine whether an address is valid."""
    try:
        ip_address = netaddr.IPAddress(ip_address_str)
        if ip_address.version != network.version:
            msg = ("Invalid IP version - must match network version " +
                   ip_version_to_string(network.version))
            raise exceptions.ValidateFail(msg)
        elif ip_address == network:
            raise exceptions.ValidateFail("Cannot use network address")
        elif ip_address == network.broadcast:
            raise exceptions.ValidateFail("Cannot use broadcast address")
        elif ip_address not in network:
            raise exceptions.ValidateFail(
                "Address must be in subnet %s" % str(network))
        return ip_address
    except netaddr.AddrFormatError:
        raise exceptions.ValidateFail(
            "Invalid address - not a valid IP address")


def ip_version_to_string(ip_version):
    """Returns a string representation of ip_version."""
    if ip_version == 4:
        return "IPv4"
    elif ip_version == 6:
        return "IPv6"
    else:
        return "IP"


def validate_network_str(network_str, minimum_size,
                         existing_networks=None, multicast=False):
    """Determine whether a network is valid."""
    try:
        network = netaddr.IPNetwork(network_str)
        if network.size < minimum_size:
            raise exceptions.ValidateFail("Subnet too small - must have at "
                                          "least %d addresses" % minimum_size)
        elif network.version == 6 and network.prefixlen < 64:
            raise exceptions.ValidateFail("IPv6 minimum prefix length is 64")
        elif existing_networks:
            if any(network.ip in subnet for subnet in existing_networks):
                raise exceptions.ValidateFail("Subnet overlaps with another "
                                              "configured subnet")
        elif multicast and not network.is_multicast():
            raise exceptions.ValidateFail("Invalid subnet - must be multicast")
        return network
    except netaddr.AddrFormatError:
        raise exceptions.ValidateFail(
            "Invalid subnet - not a valid IP subnet")


# to do validate the quota limits
def validate_quota_limits(payload):
    for resource in payload:
        # Check valid resource name
        if resource not in itertools.chain(dcorch_consts.CINDER_QUOTA_FIELDS,
                                           dcorch_consts.NOVA_QUOTA_FIELDS,
                                           dcorch_consts.NEUTRON_QUOTA_FIELDS):
            raise exceptions.InvalidInputError
        # Check valid quota limit value in case for put/post
        if isinstance(payload, dict) and (not isinstance(
                payload[resource], int) or payload[resource] <= 0):
            raise exceptions.InvalidInputError


def get_sw_update_opts(context,
                       for_sw_update=False, subcloud_id=None):
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
            sw_update_opts_ref = db_api.sw_update_opts_get(context,
                                                           subcloud_id)
            if sw_update_opts_ref:
                subcloud_name = db_api.subcloud_get(context, subcloud_id).name
                return db_api.sw_update_opts_w_name_db_model_to_dict(
                    sw_update_opts_ref, subcloud_name)
            elif for_sw_update:
                sw_update_opts_ref = db_api.sw_update_opts_default_get(context)
                if not sw_update_opts_ref:
                    sw_update_opts_dict = vim.SW_UPDATE_OPTS_CONST_DEFAULT
                    return sw_update_opts_dict
            else:
                raise exceptions.SubcloudPatchOptsNotFound(
                    subcloud_id=subcloud_id)

        return db_api.sw_update_opts_w_name_db_model_to_dict(
            sw_update_opts_ref, dccommon_consts.SW_UPDATE_DEFAULT_TITLE)


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
            LOG.exception("makedir %s OSError=%s encountered" %
                          (lock_path, e))
            return None

    return lock_path


def synchronized(name, external=True, fair=False):
    if external:
        prefix = 'DCManager-'
        lock_path = ensure_lock_path()
    else:
        prefix = None
        lock_path = None

    return lockutils.synchronized(name, lock_file_prefix=prefix,
                                  external=external, lock_path=lock_path,
                                  semaphores=None, delay=0.01, fair=fair)


def get_filename_by_prefix(dir_path, prefix):
    for filename in os.listdir(dir_path):
        if filename.startswith(prefix):
            return filename
    return None


def create_subcloud_inventory(subcloud, inventory_file):
    """Create the ansible inventory file for the specified subcloud"""

    # Delete the file if it already exists
    delete_subcloud_inventory(inventory_file)

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


def delete_subcloud_inventory(inventory_file):
    """Delete the ansible inventory file for the specified subcloud"""

    # Delete the file if it exists
    if os.path.isfile(inventory_file):
        os.remove(inventory_file)


def get_vault_load_files(target_version):
    """Return a tuple for the ISO and SIG for this load version from the vault.

    The files can be imported to the vault using any name, but must end
    in 'iso' or 'sig'.
    : param target_version: The software version to search under the vault
    """
    vault_dir = "{}/{}/".format(consts.LOADS_VAULT_DIR, target_version)

    matching_iso = None
    matching_sig = None
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
            file_type='.iso', vault_dir=vault_dir)
    if matching_sig is None:
        raise exceptions.VaultLoadMissingError(
            file_type='.sig', vault_dir=vault_dir)

    # return the iso and sig for this load
    return (matching_iso, matching_sig)
