# Copyright (c) 2020-2022 Wind River Systems, Inc.
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
import re

from eventlet.green import subprocess
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon import consts
from dccommon import exceptions
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon.subprocess_cleanup import SubprocessCleanup
from dcorch.common.i18n import _

LOG = logging.getLogger(__name__)
ANSIBLE_PASSWD_PARMS = ['ansible_ssh_pass', 'ansible_become_pass']
SCRIPT_PASSWD_PARMS = ['sysadmin_password', 'password']

# Gap, in seconds, to determine whether the given token is about to expire
# These values are used to randomize the token early renewal duration and
# to distribute the new keystone creation to different audit cycles

STALE_TOKEN_DURATION_MIN = 300
STALE_TOKEN_DURATION_MAX = 480
STALE_TOKEN_DURATION_STEP = 20

# Exitcode from 'timeout' command on timeout:
TIMEOUT_EXITCODE = 124

LAST_SW_VERSION_IN_CENTOS = "22.06"


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
        '''Return the function's docstring.'''
        return self.func.__doc__

    def __get__(self, obj, objtype):
        '''Support instance methods.'''
        return functools.partial(self.__call__, obj)


def _strip_password_from_command(script_command):
    """Strip out any known password arguments from given command"""
    logged_command = list()
    for item in script_command:
        if not any(parm in item for parm in SCRIPT_PASSWD_PARMS):
            logged_command.append(item)
        else:
            tmpl = item.split()
            tmpstr = ''
            for tmp in tmpl:
                if any(parm in tmp for parm in SCRIPT_PASSWD_PARMS):
                    tmpstr = tmpstr + tmp[:tmp.index('=') + 1] + ' '
                else:
                    tmpstr = tmpstr + tmp + ' '
            tmpstr = tmpstr[:-1]
            logged_command.append(tmpstr)
    return logged_command


def run_playbook(log_file, playbook_command,
                 timeout=None, register_cleanup=True):
    """Run ansible playbook via subprocess.

    log_file: Logs output to file
    timeout: Timeout in seconds. Raises PlaybookExecutionTimeout on timeout
    register_cleanup: Register the subprocess group for cleanup on shutdown,
                      if the underlying service supports cleanup.
    """
    exec_env = os.environ.copy()
    exec_env["ANSIBLE_LOG_PATH"] = "/dev/null"

    if timeout:
        # Invoke ansible-playbook via the 'timeout' command.
        # Using --kill-after=5s which will force a kill -9 if the process
        # hasn't terminated within 5s:
        timeout_log_str = " (timeout: %ss)" % timeout
        playbook_command = ["/usr/bin/timeout", "--kill-after=5s",
                            "%ss" % timeout] + playbook_command
    else:
        timeout_log_str = ''

    with open(log_file, "a+") as f_out_log:
        try:
            logged_playbook_command = \
                _strip_password_from_command(playbook_command)
            txt = "%s Executing playbook command%s: %s\n" \
                % (datetime.today().strftime('%Y-%m-%d-%H:%M:%S'),
                   timeout_log_str,
                   logged_playbook_command)
            f_out_log.write(txt)
            f_out_log.flush()

            if register_cleanup:
                # Use the same process group / session for all children
                # This makes it easier to kill the entire process group
                # on cleanup
                preexec_fn = os.setsid
            else:
                preexec_fn = None

            # TODO(kmacleod) future considerations:
            # - In python3, this code can be simplified to use the new
            #   subprocess.run(timeout=val) method or Popen with
            #   subp.wait(timeout=val)
            # - Beginning with ansible 2.10, we can introduce the
            #   ANSIBLE_TASK_TIMEOUT value to set a task-level timeout.
            #   This is not available in our current version of ansible (2.7.5)
            subp = subprocess.Popen(playbook_command,
                                    stdout=f_out_log,
                                    stderr=f_out_log,
                                    env=exec_env,
                                    preexec_fn=preexec_fn)
            try:
                if register_cleanup:
                    SubprocessCleanup.register_subprocess_group(subp)

                subp.communicate()  # wait for process to exit

                if timeout and subp.returncode == TIMEOUT_EXITCODE:
                    f_out_log.write(
                        "%s TIMEOUT (%ss) - playbook is terminated\n" %
                        (datetime.today().strftime('%Y-%m-%d-%H:%M:%S'), timeout)
                    )
                    raise PlaybookExecutionTimeout(playbook_cmd=playbook_command,
                                                   timeout=timeout)
                if subp.returncode != 0:
                    raise PlaybookExecutionFailed(playbook_cmd=playbook_command)
            finally:
                f_out_log.flush()
                if register_cleanup:
                    SubprocessCleanup.unregister_subprocess_group(subp)

        except PlaybookExecutionFailed:
            raise
        except Exception as ex:
            LOG.error(str(ex))
            raise


def is_token_expiring_soon(token,
                           stale_token_duration_min=STALE_TOKEN_DURATION_MIN,
                           stale_token_duration_max=STALE_TOKEN_DURATION_MAX,
                           stale_token_duration_step=STALE_TOKEN_DURATION_STEP):
    expiry_time = timeutils.normalize_time(timeutils.parse_isotime(token['expires_at']))
    duration = random.randrange(stale_token_duration_min,
                                stale_token_duration_max,
                                stale_token_duration_step)
    if timeutils.is_soon(expiry_time, duration):
        return True
    return False


def _get_key_from_file(file_contents, key):
    """Extract value from KEY=VALUE entries.

    Ignore newline, ignore apostrophe, ignore quotation mark.
    :param file_contents: contents of file
    :param key: key to search
    :return: found value or ''
    """
    r = re.compile('^{}\=[\'\"]*([^\'\"\n]*)'.format(key), re.MULTILINE)
    match = r.search(file_contents)
    if match:
        return match.group(1)
    else:
        return ''


@memoized
def get_os_release(release_file=consts.OS_RELEASE_FILE):
    """Function to read release information.

    Ignore newline, ignore apostrophe, ignore quotation mark.
    :param release_file: file to read from
    :return: a tuple of (ID, VERSION)
    """
    linux_distro = ('', '')

    try:
        with open(release_file, 'r') as f:
            data = f.read()
            linux_distro = (
                _get_key_from_file(data, 'ID'),
                _get_key_from_file(data, 'VERSION'))
    except Exception as e:
        raise exceptions.DCCommonException(
            msg=_("Failed to open %s : %s" % (release_file, str(e))))

    if linux_distro[0] == '':
        raise exceptions.DCCommonException(
            msg=_("Could not determine os type from %s" % release_file))

    # Hint: This code is added here to aid future unit test.
    # Probably running unit tests on a non-supported OS (example at
    # time of writing: ubuntu), which is perfect, because code reaching
    # here will fail, and we just identified a place that would split
    # logic between OSs. The failing tests should mock this function
    # (get_os_release) for each supported OS.
    if linux_distro[0] not in consts.SUPPORTED_OS_TYPES:
        raise exceptions.DCCommonException(
            msg=_("Unsupported OS detected %s" % linux_distro[0]))

    return linux_distro


def get_os_type(release_file=consts.OS_RELEASE_FILE):
    return get_os_release(release_file)[0]


def is_debian(software_version=None):
    """Check target version or underlying OS type.

    Check either the given software_version (e.g. for checking a subcloud,
    or prestaging operation), or the underlying OS type (for this running
    instance)
    """
    if software_version:
        return not is_centos(software_version)
    return get_os_type() == consts.OS_DEBIAN


def is_centos(software_version=None):
    """Check target version or underlying OS type.

    Check either the given software_version (e.g. for checking a subcloud,
    or prestaging operation), or the underlying OS type (for this running
    instance)
    """
    if software_version:
        return software_version <= LAST_SW_VERSION_IN_CENTOS
    return get_os_type() == consts.OS_CENTOS


def get_ssl_cert_ca_file():
    return os.path.join(
        consts.SSL_CERT_CA_DIR,
        consts.CERT_CA_FILE_DEBIAN if is_debian() else consts.CERT_CA_FILE_CENTOS)
