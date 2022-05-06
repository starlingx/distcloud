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

from datetime import datetime
import os
import random

from eventlet.green import subprocess
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon.subprocess_cleanup import SubprocessCleanup

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
