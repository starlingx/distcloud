#
# Copyright (c) 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import signal
import time

from oslo_concurrency import lockutils
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class SubprocessCleanup(object):
    """Lifecycle manager for subprocesses spawned via python subprocess.

    Notes:
    - This is a best-effort cleanup. We need to preserve fast shutdown
      times in case of a SWACT.
    - There could potentially be multiple hundreds of subprocesses needing
      to be cleaned up here.
    """

    LOCK_NAME = "subprocess-cleanup"
    SUBPROCESS_GROUPS = {}

    @staticmethod
    def register_subprocess_group(subprocess_p):
        SubprocessCleanup.SUBPROCESS_GROUPS[subprocess_p.pid] = subprocess_p

    @staticmethod
    def unregister_subprocess_group(subprocess_p):
        SubprocessCleanup.SUBPROCESS_GROUPS.pop(subprocess_p.pid, None)

    @staticmethod
    @lockutils.synchronized(LOCK_NAME)
    def shutdown_cleanup(origin="service"):
        SubprocessCleanup._shutdown_subprocess_groups(origin)

    @staticmethod
    def _shutdown_subprocess_groups(origin):
        num_process_groups = len(SubprocessCleanup.SUBPROCESS_GROUPS)
        if num_process_groups > 0:
            LOG.warn(
                "Shutting down %d process groups via %s", num_process_groups, origin
            )
            start_time = time.time()
            for _, subp in SubprocessCleanup.SUBPROCESS_GROUPS.items():
                kill_subprocess_group(subp)
            LOG.info(
                "Time for %s child processes to exit: %s",
                num_process_groups,
                time.time() - start_time,
            )


def kill_subprocess_group(subp, logmsg=None):
    """Kill the subprocess and any children."""
    exitcode = subp.poll()
    if exitcode:
        LOG.info(
            "kill_subprocess_tree: subprocess has already "
            "terminated, pid: %s, exitcode=%s",
            subp.pid,
            exitcode,
        )
        return False

    if logmsg:
        LOG.warn(logmsg)
    else:
        LOG.warn("Killing subprocess group for pid: %s, args: %s", subp.pid, subp.args)
    # Send a SIGTERM (normal kill). We do not verify if the processes
    # are shutdown (best-effort), since we don't want to wait around before
    # issueing a SIGKILL (fast shutdown)
    os.killpg(subp.pid, signal.SIGTERM)
    return True
