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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from datetime import datetime
from eventlet.green import subprocess
import os
from oslo_log import log as logging

from dccommon.exceptions import PlaybookExecutionFailed

LOG = logging.getLogger(__name__)
ANSIBLE_PASSWD_PARMS = ['ansible_ssh_pass', 'ansible_become_pass']


def run_playbook(log_file, playbook_command):
    exec_env = os.environ.copy()
    exec_env["ANSIBLE_LOG_PATH"] = "/dev/null"

    with open(log_file, "a+") as f_out_log:
        try:
            timestamp = datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
            logged_playbook_command = []
            for item in playbook_command:
                if not any(parm in item for parm in ANSIBLE_PASSWD_PARMS):
                    logged_playbook_command.append(item)
                else:
                    tmpl = item.split()
                    tmpstr = ''
                    for tmp in tmpl:
                        if any(parm in tmp for parm in ANSIBLE_PASSWD_PARMS):
                            tmpstr = tmpstr + tmp[:tmp.index('=') + 1] + ' '
                        else:
                            tmpstr = tmpstr + tmp + ' '
                    tmpstr = tmpstr[:-1]
                    logged_playbook_command.append(tmpstr)

            txt = "%s Executing playbook command: %s\n" % (timestamp, logged_playbook_command)
            f_out_log.write(txt)
            f_out_log.flush()

            subprocess.check_call(  # pylint: disable=E1102
                playbook_command,
                stdout=f_out_log,
                stderr=f_out_log,
                env=exec_env)
        except subprocess.CalledProcessError:
            raise PlaybookExecutionFailed(playbook_cmd=playbook_command)
        except Exception as e:
            LOG.error(str(e))
            raise
