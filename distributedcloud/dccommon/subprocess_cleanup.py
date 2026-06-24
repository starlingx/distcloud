#
# Copyright (c) 2022, 2024, 2026 Wind River Systems, Inc.
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
    _IS_SHUTTING_DOWN = False

    @staticmethod
    def register_subprocess_group(subprocess_p):
        SubprocessCleanup.SUBPROCESS_GROUPS[subprocess_p.pid] = subprocess_p

    @staticmethod
    def unregister_subprocess_group(subprocess_p):
        SubprocessCleanup.SUBPROCESS_GROUPS.pop(subprocess_p.pid, None)

    @staticmethod
    @lockutils.synchronized(LOCK_NAME)
    def shutdown_cleanup(origin="service"):
        SubprocessCleanup._IS_SHUTTING_DOWN = True
        SubprocessCleanup._shutdown_subprocess_groups(origin)

    @staticmethod
    def is_shutting_down():
        return SubprocessCleanup._IS_SHUTTING_DOWN

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


def _get_children_recursive(pid):
    """Recursively find all descendant PIDs via /proc."""
    children = []
    try:
        tasks_dir = "/proc/%d/task" % pid
        if not os.path.exists(tasks_dir):
            return children
        for tid in os.listdir(tasks_dir):
            children_file = "%s/%s/children" % (tasks_dir, tid)
            try:
                with open(children_file, "r") as f:
                    for child_pid_str in f.read().split():
                        child_pid = int(child_pid_str)
                        children.append(child_pid)
                        children.extend(_get_children_recursive(child_pid))
            except (FileNotFoundError, ValueError, PermissionError):
                pass
    except (FileNotFoundError, PermissionError):
        pass
    return children


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

    # Send SIGTERM to the process group (best-effort graceful shutdown)
    os.killpg(subp.pid, signal.SIGTERM)

    # Also SIGKILL the entire process tree. This handles ansible-core >= 2.18
    # where workers call os.setsid() and escape the original process group,
    # making them unreachable via killpg. We don't wait around since we need
    # fast shutdown.
    children = _get_children_recursive(subp.pid)
    if children:
        LOG.info("Sending SIGKILL to %d descendant PIDs of %s", len(children), subp.pid)
        for child_pid in children:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    return True
