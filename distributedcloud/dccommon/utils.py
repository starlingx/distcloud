# Copyright (c) 2020-2025 Wind River Systems, Inc.
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

import collections
from datetime import datetime
import functools
import os
import random
import threading
import time
from typing import Callable

from eventlet.green import subprocess
import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon import consts
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon import rvmc
from dccommon.subprocess_cleanup import kill_subprocess_group
from dccommon.subprocess_cleanup import SubprocessCleanup

CONF = cfg.CONF

LOG = logging.getLogger(__name__)
ANSIBLE_PASSWD_PARMS = ["ansible_ssh_pass", "ansible_become_pass"]
SCRIPT_PASSWD_PARMS = ["sysadmin_password", "password"]

# Gap, in seconds, to determine whether the given token is about to expire
# These values are used to randomize the token early renewal duration and
# to distribute the new keystone creation to different audit cycles

STALE_TOKEN_DURATION_MIN = 300
STALE_TOKEN_DURATION_MAX = 480
STALE_TOKEN_DURATION_STEP = 20

# Exitcode from 'timeout' command on timeout:
TIMEOUT_EXITCODE = 124


class memoized(object):
    """Decorator.

    Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).

    WARNING:  This function should not be used for class methods since it
    does not provide weak references; thus would prevent the instance from
    being garbage collected.
    """

    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            # uncacheable. a list, for instance.
            # better to not cache than blow up.
            return self.func(*args)
        if args in self.cache:
            return self.cache[args]
        else:
            value = self.func(*args)
            self.cache[args] = value
            return value

    def __repr__(self):
        """Return the function's docstring."""
        return self.func.__doc__

    def __get__(self, obj, objtype):
        """Support instance methods."""
        return functools.partial(self.__call__, obj)


class AnsiblePlaybook(object):
    """Class to run Ansible playbooks with the abort option

    Approach:

    At the start of the playbook execution, the abort status
    (default value is False) and PID of the subprocess for the
    specified subcloud are set on the class variable dict (abort_status).
    When the user sends the abort command, the subcloud_manager changes
    the abort status to True and the subprocess is killed.

    If Ansible is currently executing a task that cannot be interrupted,
    a deploy_not_abortable flag is created in the overrides folder by the
    playbook itself, and the abort process will wait for said flag to be
    deleted before killing the subprocess. If the task fails while abort
    is waiting, the playbook_failed flag will indicate to the
    original process to raise PlaybookExecutionFailed.
    """

    abort_status = {}
    lock = threading.Lock()

    def __init__(self, subcloud_name: str):
        self.subcloud_name = subcloud_name

    def _unregister_subcloud(self):
        with AnsiblePlaybook.lock:
            if AnsiblePlaybook.abort_status.get(self.subcloud_name):
                del AnsiblePlaybook.abort_status[self.subcloud_name]

    def run_abort(self, timeout=600):
        """Set abort status for a subcloud.

        :param subcloud_name: Name of the subcloud
        param timeout: Timeout in seconds.
        """
        with AnsiblePlaybook.lock:
            AnsiblePlaybook.abort_status[self.subcloud_name]["abort"] = True
        unabortable_flag = os.path.join(
            consts.ANSIBLE_OVERRIDES_PATH,
            ".%s_deploy_not_abortable" % self.subcloud_name,
        )
        subp = AnsiblePlaybook.abort_status[self.subcloud_name]["subp"]
        while os.path.exists(unabortable_flag) and timeout > 0:
            # If subprocess ended (subp.poll is not None), no further abort
            # action is necessary
            if subp.poll():
                return False
            time.sleep(1)
            timeout -= 1
        return kill_subprocess_group(subp)

    def run_playbook(
        self, log_file, playbook_command, timeout=None, register_cleanup=True
    ):
        """Run ansible playbook via subprocess.

        :param log_file: Logs output to file
        :param timeout: Timeout in seconds. Raises PlaybookExecutionTimeout
         on timeout
        :param register_cleanup: Register the subprocess group for cleanup on
         shutdown, if the underlying service supports cleanup.
        """
        exec_env = os.environ.copy()
        exec_env["ANSIBLE_LOG_PATH"] = "/dev/null"

        aborted = False

        if timeout:
            timeout_log_str = " (timeout: %ss)" % timeout
        else:
            timeout_log_str = ""

        with open(log_file, "a+") as f_out_log:
            try:
                logged_playbook_command = _strip_password_from_command(playbook_command)
                txt = "%s Executing playbook command%s: %s\n" % (
                    datetime.today().strftime("%Y-%m-%d-%H:%M:%S"),
                    timeout_log_str,
                    logged_playbook_command,
                )
                f_out_log.write(txt)
                f_out_log.flush()

                # Remove unabortable flag created by the playbook
                # if present from previous executions
                unabortable_flag = os.path.join(
                    consts.ANSIBLE_OVERRIDES_PATH,
                    ".%s_deploy_not_abortable" % self.subcloud_name,
                )
                if os.path.exists(unabortable_flag):
                    os.remove(unabortable_flag)

                subp = subprocess.Popen(
                    playbook_command,
                    stdout=f_out_log,
                    stderr=f_out_log,
                    env=exec_env,
                    start_new_session=register_cleanup,
                )
                try:
                    if register_cleanup:
                        SubprocessCleanup.register_subprocess_group(subp)
                    with AnsiblePlaybook.lock:
                        AnsiblePlaybook.abort_status[self.subcloud_name] = {
                            "abort": False,
                            "subp": subp,
                        }

                    subp.wait(timeout)
                    subp_rc = subp.poll()

                    # There are 5 possible outcomes of the subprocess execution:
                    # 1: Playbook completed (process exited)
                    #    - playbook_failure is False with subp_rc == 0,
                    #      aborted is False, unabortable_flag_exists is False
                    # 2: Playbook was aborted (process killed)
                    #    - playbook_failure is False with subp_rc != 0,
                    #      aborted is True, unabortable_flag_exists is False
                    # 3: Playbook failed (process exited)
                    #    - playbook_failure is True with subp_rc != 0,
                    #      aborted is False, unabortable_flag_exists is False
                    # 4: Playbook failed during unabortable task (process exited)
                    #    - playbook_failure is True with  subp_rc != 0,
                    #      aborted is False, unabortable_flag_exists is True
                    # 5: Playbook failed while waiting to be aborted (process exited)
                    #    - playbook_failure is True with subp_rc != 0,
                    #      aborted is True, unabortable_flag_exists is False
                    with AnsiblePlaybook.lock:
                        aborted = AnsiblePlaybook.abort_status[self.subcloud_name][
                            "abort"
                        ]
                        unabortable_flag_exists = os.path.exists(unabortable_flag)
                    playbook_failure = subp_rc != 0 and (
                        not aborted or unabortable_flag_exists
                    )

                    # Raise PlaybookExecutionFailed if the playbook fails when
                    # on normal conditions (no abort issued) or fails while
                    # waiting for the unabortable flag to be cleared.
                    if playbook_failure:
                        raise PlaybookExecutionFailed(playbook_cmd=playbook_command)

                except subprocess.TimeoutExpired:
                    kill_subprocess_group(subp)
                    f_out_log.write(
                        "%s TIMEOUT (%ss) - playbook is terminated\n"
                        % (datetime.today().strftime("%Y-%m-%d-%H:%M:%S"), timeout)
                    )
                    raise PlaybookExecutionTimeout(
                        playbook_cmd=playbook_command, timeout=timeout
                    )
                finally:
                    f_out_log.flush()
                    if register_cleanup:
                        SubprocessCleanup.unregister_subprocess_group(subp)
                    self._unregister_subcloud()

            except PlaybookExecutionFailed:
                raise
            except Exception as ex:
                LOG.error(str(ex))
                raise
        return aborted


def _strip_password_from_command(script_command):
    """Strip out any known password arguments from given command"""
    logged_command = list()
    for item in script_command:
        if not any(parm in item for parm in SCRIPT_PASSWD_PARMS):
            logged_command.append(item)
        else:
            tmpl = item.split()
            tmpstr = ""
            for tmp in tmpl:
                if any(parm in tmp for parm in SCRIPT_PASSWD_PARMS):
                    tmpstr = tmpstr + tmp[: tmp.index("=") + 1] + " "
                else:
                    tmpstr = tmpstr + tmp + " "
            tmpstr = tmpstr[:-1]
            logged_command.append(tmpstr)
    return logged_command


def is_token_expiring_soon(
    token,
    stale_token_duration_min=STALE_TOKEN_DURATION_MIN,
    stale_token_duration_max=STALE_TOKEN_DURATION_MAX,
    stale_token_duration_step=STALE_TOKEN_DURATION_STEP,
):
    try:
        expiry_time = timeutils.normalize_time(
            timeutils.parse_isotime(token["expires_at"])
        )
    except KeyError:
        LOG.warning("Token is missing 'expires_at' field, considering it as expired")
        return True
    duration = random.randrange(
        stale_token_duration_min, stale_token_duration_max, stale_token_duration_step
    )
    if timeutils.is_soon(expiry_time, duration):
        return True
    return False


def get_ssl_cert_ca_file():
    return os.path.join(consts.SSL_CERT_CA_DIR, consts.CERT_CA_FILE_DEBIAN)


def send_subcloud_shutdown_signal(subcloud_name):
    """Sends a shutdown signal to a Redfish controlled subcloud.

    :param subcloud_name: the name of the subcloud to be shut down
    :type subcloud_name: str
    """
    # All logs are expected to originate from the rvmc module,
    # so the log churn from the 'redfish.rest.v1' module is disabled.
    logging.getLogger("redfish.rest.v1").setLevel(logging.CRITICAL)

    rvmc_config_file = os.path.join(
        consts.ANSIBLE_OVERRIDES_PATH, subcloud_name, consts.RVMC_CONFIG_FILE_NAME
    )
    rvmc.power_off(subcloud_name, rvmc_config_file, LOG)


def subcloud_has_dcagent(software_version: str):
    return software_version >= consts.MIN_VERSION_FOR_DCAGENT


def convert_resource_to_dict(resource):
    if isinstance(resource, dict) or (
        isinstance(resource, list) and all(isinstance(item, dict) for item in resource)
    ):
        # Return the resource if already in the desired format
        return resource
    if hasattr(resource, "to_dict"):
        return resource.to_dict()
    elif isinstance(resource, list):
        return [r.to_dict() for r in resource if hasattr(r, "to_dict")]
    raise TypeError(
        "Resource must be a dictionary, a list of dictionaries, "
        "or an object/list of objects with a 'to_dict' method."
    )


def log_subcloud_msg(
    log_func: Callable, msg: str, subcloud_name: str = None, avail_status: str = None
):
    prefix = ""
    if subcloud_name:
        prefix += f"Subcloud: {subcloud_name}. "
    if avail_status:
        prefix += f"Availability: {avail_status}. "
    log_func(f"{prefix}{msg}")


def build_subcloud_endpoint_map(ip: str) -> dict:
    """Builds a mapping of service endpoints for a given IP address.

    :param ip: The IP address for which service endpoints need to be mapped.
    :type ip: str
    :return: A dictionary containing service names as keys and formatted
             endpoint URLs as values.
    :rtype: dict
    """
    endpoint_map = {}
    for service, endpoint in consts.ENDPOINT_URLS.items():
        formatted_ip = f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
        endpoint_map[service] = endpoint.format(formatted_ip)
    return endpoint_map


def build_subcloud_endpoints(subcloud_mgmt_ips: dict) -> dict:
    """Builds a dictionary of service endpoints for multiple subcloud management IPs.

    :param subcloud_mgmt_ips: A dictionary containing subcloud regions as keys
                              and the corresponding management IP as value.
    :type subcloud_mgmt_ips: dict
    :return: A dictionary with subcloud regions as keys and their respective
        service endpoints as values.
    :rtype: dict
    """
    subcloud_endpoints = {}
    for region, ip in subcloud_mgmt_ips.items():
        subcloud_endpoints[region] = build_subcloud_endpoint_map(ip)
    return subcloud_endpoints


def build_subcloud_endpoint(ip: str, service: str) -> str:
    """Builds a service endpoint for a given IP address.

    :param ip: The IP address for constructing the service endpoint.
    :type ip: str
    :param service: The service of the endpoint
    :type service: str
    :return: The service endpoint URL.
    :type: str
    """
    endpoint = consts.ENDPOINT_URLS.get(service, None)
    if endpoint:
        formatted_ip = f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
        endpoint = endpoint.format(formatted_ip)
    return endpoint


@functools.lru_cache(maxsize=1)
def get_region_one_name() -> str:
    return CONF.keystone_authtoken.region_name


@functools.lru_cache(maxsize=1)
def get_system_controller_region_names() -> tuple[str]:
    return (consts.SYSTEM_CONTROLLER_NAME, CONF.keystone_authtoken.region_name)


def is_region_one(region_name: str) -> bool:
    return region_name == get_region_one_name()


def is_system_controller_region(region_name: str) -> bool:
    return region_name in get_system_controller_region_names()
