# Copyright 2015 Huawei Technologies Co., Ltd.
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

import datetime
import grp
import itertools
import netaddr
import os
import pwd
import re
import six.moves
import subprocess
import tsconfig.tsconfig as tsc

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon import exceptions as dccommon_exceptions
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.db import api as db_api

from dccommon.drivers.openstack import vim

from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

LOG = logging.getLogger(__name__)

DC_MANAGER_USERNAME = "root"
DC_MANAGER_GRPNAME = "root"

# Max lines output msg from logs
MAX_LINES_MSG = 10


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

    params_supported = ['C', 'OU', 'O', 'ST', 'CN', 'L']
    subject_pairs = re.findall(r"([^=]+=[^=]+)(?:\s|$)", subject)
    subject_dict = {}
    for pair_value in subject_pairs:
        key, value = pair_value.split("=")
        subject_dict[key] = value

    if not all([param in params_supported for param in subject_dict.keys()]):
        return False, ("There are parameters not supported "
                       "for the certificate subject specification. "
                       "The subject parameter has to be in the "
                       "format of 'C=<Country> ST=<State/Province> "
                       "L=<Locality> O=<Organization> OU=<OrganizationUnit> "
                       "CN=<commonName>")
    if 'CN' not in list(subject_dict.keys()):
        return False, ("The CN=<commonName> parameter is required to be "
                       "specified in subject argument")
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
        return False, ("expiry_date %s doesn't match format "
                       "YYYY-MM-DD" % expiry_date)

    delta = date - datetime.datetime.now()
    # we sum one day (24 hours) to accomplish the certificate expiry
    # during the day specified by the user
    duration = (delta.days * 24 + 24)

    # Cert-manager manages certificates and renew them some time
    # before it expires. Along this procedure we set renewBefore
    # parameter for 24h, so we are checking if the duration sent
    # has at least this amount of time. This is needed to avoid
    # cert-manager to block the creation of the resources.
    if duration <= 24:
        return False, ("New k8s rootCA should have at least 24 hours of "
                       "validation before expiry.")
    return True, ""


# to do validate the quota limits
def validate_quota_limits(payload):
    for resource in payload:
        # Check valid resource name
        if resource not in itertools.chain(dccommon_consts.CINDER_QUOTA_FIELDS,
                                           dccommon_consts.NOVA_QUOTA_FIELDS,
                                           dccommon_consts.NEUTRON_QUOTA_FIELDS):
            raise exceptions.InvalidInputError
        # Check valid quota limit value in case for put/post
        if isinstance(payload, dict) and (not isinstance(
                payload[resource], int) or payload[resource] <= 0):
            raise exceptions.InvalidInputError


def get_sw_update_strategy_extra_args(context, update_type=None):
    """Query an existing sw_update_strategy for its extra_args.

    :param context: request context object.
    :param update_type: filter the update strategy (defaults to None)
    :returns dict (returns an empty dictionary if no strategy exists)
    """
    try:
        sw_update_strategy = \
            db_api.sw_update_strategy_get(context,
                                          update_type=update_type)
        return sw_update_strategy.extra_args
    except exceptions.NotFound:
        # return an empty dictionary if there is no strategy
        return {}


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
    """Returns the first filename found matching 'prefix' within 'dir_path'

    Note: returns base filename only - result does not include dir_path
    """
    for filename in os.listdir(dir_path):
        if filename.startswith(prefix):
            return filename
    return None


def create_subcloud_inventory(subcloud,
                              inventory_file):
    """Create the ansible inventory file for the specified subcloud"""

    # Delete the file if it already exists
    delete_subcloud_inventory(inventory_file)

    with open(inventory_file, 'w') as f_out_inventory:
        f_out_inventory.write(
            '---\n'
            'all:\n'
            '  vars:\n'
            '    ansible_ssh_user: sysadmin\n'
            '    ansible_ssh_extra_args: "-o UserKnownHostsFile=/dev/null"\n'
            '  hosts:\n'
            '    ' + subcloud['name'] + ':\n'
            '      ansible_host: ' +
            subcloud['bootstrap-address'] + '\n'
        )


def create_subcloud_inventory_with_admin_creds(subcloud_name,
                                               inventory_file,
                                               subcloud_bootstrap_address,
                                               ansible_pass):
    """Create the ansible inventory file for the specified subcloud.

    Includes ansible_become_pass attribute.
    """

    # Delete the file if it already exists
    delete_subcloud_inventory(inventory_file)

    with open(inventory_file, 'w') as f_out_inventory:
        f_out_inventory.write(
            ('---\n'
             'all:\n'
             '  vars:\n'
             '    ansible_ssh_user: sysadmin\n'
             '    ansible_ssh_pass: {0}\n'
             '    ansible_become_pass: {0}\n'
             '    ansible_ssh_extra_args: "-o UserKnownHostsFile=/dev/null"\n'
             '  hosts:\n'
             '    {1}:\n'
             '      ansible_host: {2}\n').format(ansible_pass,
                                                 subcloud_name,
                                                 subcloud_bootstrap_address)
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
                file_type='.iso', vault_dir=vault_dir)
        if matching_sig is None:
            raise exceptions.VaultLoadMissingError(
                file_type='.sig', vault_dir=vault_dir)

    # return the iso and sig for this load
    return (matching_iso, matching_sig)


def get_active_kube_version(kube_versions):
    """Returns the active (target) kubernetes from a list of versions"""

    matching_kube_version = None
    for kube in kube_versions:
        kube_dict = kube.to_dict()
        if kube_dict.get('target') and kube_dict.get('state') == 'active':
            matching_kube_version = kube_dict.get('version')
            break
    return matching_kube_version


def get_available_kube_version(kube_versions):
    """Returns first available kubernetes version from a list of versions"""

    matching_kube_version = None
    for kube in kube_versions:
        kube_dict = kube.to_dict()
        if kube_dict.get('state') == 'available':
            matching_kube_version = kube_dict.get('version')
            break
    return matching_kube_version


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
    if left is None or right is None or left[0] != 'v' or right[0] != 'v':
        raise Exception("Invalid kube version(s), left: (%s), right: (%s)" %
                        (left, right))
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


def get_loads_for_patching(loads):
    """Filter the loads that can be patched. Return their software versions"""
    valid_states = [
        consts.ACTIVE_LOAD_STATE,
        consts.IMPORTED_LOAD_STATE
    ]
    return [load.software_version for load in loads if load.state in valid_states]


def subcloud_get_by_ref(context, subcloud_ref):
    """Handle getting a subcloud by either name, or ID

    :param context: The request context
    :param subcloud_ref: Reference to the subcloud, either a name or an ID
    """
    try:
        return db_api.subcloud_get(context, subcloud_ref) \
            if subcloud_ref.isdigit() \
            else db_api.subcloud_get_by_name(context, subcloud_ref)
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


def subcloud_db_list_to_dict(subclouds):
    return {'subclouds': [db_api.subcloud_db_model_to_dict(subcloud)
            for subcloud in subclouds]}


def get_oam_addresses(subcloud_name, sc_ks_client):
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
                   subcloud_name)
        LOG.error(message)
    return None


def get_ansible_filename(subcloud_name, postfix='.yml'):
    """Build ansible filename using subcloud and given postfix"""
    ansible_filename = os.path.join(consts.ANSIBLE_OVERRIDES_PATH,
                                    subcloud_name + postfix)
    return ansible_filename


def pre_check_management_affected_alarm(system_health):
    """Acceptable health conditions:

    a) subcloud is completely healthy (i.e. no failed checks)
    b) there is alarm but no management affecting alarm
    c) subcloud fails alarm check and it only has non-management
       affecting alarm(s)
    """
    failed_alarm_check = re.findall("No alarms: \[Fail\]", system_health)
    no_mgmt_alarms = re.findall("\[0\] of which are management affecting",
                                system_health)
    if failed_alarm_check and not no_mgmt_alarms:
        return False
    return True


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
    failed_task = ''
    files_for_search = []

    cmd_1 = 'awk'
    # awk command to get the information iside the last match found
    # starting with 'fatal: [' and ending with 'PLAY RECAP'.
    cmd_2 = ('''BEGIN {f=""}                # initialize f
        /fatal: \[/ {f=""}                  # reset f on first match
        /fatal: \[/,/PLAY RECAP/ {          # capture text between two delimiters
            if ($0 ~ /PLAY RECAP/) next     # exclude last delimiter
            if ($0 == "") next              # exclude blank line
            f = f ? (f "\\n" $0) : $0}      # assign or append to f
            END {print f}
            ''')

    # necessary check since is possible to have
    # the error in rotated ansible log
    log_file_temp = log_file + '.1'
    if os.path.exists(log_file_temp):
        files_for_search.append(log_file_temp)
        if os.path.exists(log_file):
            files_for_search.append(log_file)
    else:
        files_for_search.append(log_file)

    if (len(files_for_search) < 2):
        cmd_list = ([cmd_1, cmd_2, files_for_search[0]])
    else:
        cmd_list = ([cmd_1, cmd_2, files_for_search[0], files_for_search[1]])

    try:
        error_msg_raw = subprocess.check_output(
            cmd_list,
            stderr=subprocess.STDOUT).decode('utf-8')
        if len(error_msg_raw) > 1:
            error_found = True
            error_msg = [elem for elem in error_msg_raw.split("\n") if elem]
            failed_task = get_failed_task(files_for_search)
    except Exception as exc:
        LOG.error("Failed getting info from ansible log file :%s" % exc)

    if error_found and (len(error_msg) > MAX_LINES_MSG):
        error_msg = summarize_message(error_msg)
    error_msg = '\n'.join(str(element) for element in error_msg)
    error_msg = error_msg.replace("\'", "\"")

    if error_found:
        msg = "FAILED %s playbook of (%s).\n" \
            " detail: %s \n" \
            "FAILED TASK: %s " % (
                stage,
                subcloud_name,
                error_msg,
                failed_task)
    else:
        msg = "FAILED %s playbook of (%s).\n" \
            "check individual log at " \
            "%s for detailed output " % (
                stage,
                subcloud_name,
                log_file)
    return msg


def get_failed_task(files):
    """Get last task failed

    It receives an ansible log file (or a couple of files)
    and search for the last failed task with its date

    Returns a string with the task and date
    """

    cmd_1 = 'awk'
    # awk command to get the information about last failed task.
    # Match expression starting with 'TASK [' and ending with
    # 'fatal: ['
    cmd_2 = ('''BEGIN {f=""}            # initialize f
        /TASK \[/ {f=""}                # reset f on first match
        /TASK \[/,/fatal: \[/ {         # capture text between two delimiters
            if ($0 ~ /fatal: \[/) next  # exclude last delimiter
            if ($0 == "") next          # exclude blank line
            f = f ? (f "\\n" $0) : $0}  # assign or append to f
            END {print f}
            ''')
    # necessary check since is possible to have
    # the error in rotated ansible log
    if (len(files) < 2):
        awk_cmd = ([cmd_1, cmd_2, files[0]])
    else:
        awk_cmd = ([cmd_1, cmd_2, files[0], files[1]])

    try:
        failed_task = subprocess.check_output(
            awk_cmd,
            stderr=subprocess.STDOUT).decode('utf-8')
        if len(failed_task) < 1:
            return None
    except Exception as exc:
        LOG.error("Failed getting failed task :%s" % exc)
        return None
    failed_task = failed_task.replace("*", "")
    failed_task = failed_task.replace("\'", "\"")
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
    list_of_strings_to_search_for = [
        'msg:', 'fail', 'error', 'cmd', 'stderr'
        ]
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
