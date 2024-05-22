# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

from oslo_log import log as logging
import sh

from dcmanager.common import utils

# The 'sh' library is magical - it looks up CLI functions dynamically.
# Disable the pylint warnings here:
# pylint: disable=not-callable,no-member

LOG = logging.getLogger(__name__)


def check_stale_bindmount(mount_path, source_path, log_error=True):
    """Check if the mount has become stale.

    We do this by comparing the directory inodes. If the bind mount is
    valid, the two directories should have the same inode number; otherwise
    the original directory has been replaced and we are no longer tracking
    the actual location of source_path. In this case we teardown the bind
    mount.
    """
    mount_path_inode = sh.stat("--format", "%i", mount_path)
    source_path_inode = sh.stat("--format", "%i", source_path)
    if mount_path_inode != source_path_inode:
        logmsg = f"Found stale bind mount: {mount_path}, unmounting"
        if log_error:
            LOG.error(logmsg)
        else:
            LOG.warn(logmsg)
        try:
            sh.umount(mount_path)
            os.rmdir(mount_path)
        except Exception:
            LOG.error(f"Failed to fix bind mount at {mount_path}")
            raise
        return True

    return False


# TODO(kmacleod): utils.synchronized should be moved into dccommon
@utils.synchronized("ostree-mount-subclouds", external=True)
def validate_ostree_iso_mount(www_iso_root, source_path):
    """Ensure the ostree_repo is properly mounted under the iso path.

    Validity check includes if the mount is stale.
    If stale, the bind mount is recreated.
    Note that ostree_repo is mounted in a location not specific to a subcloud.
    """
    ostree_repo_mount_path = os.path.join(www_iso_root, "ostree_repo")
    LOG.debug("Checking ostree_repo mount: %s", ostree_repo_mount_path)
    if os.path.exists(ostree_repo_mount_path) and check_stale_bindmount(
        ostree_repo_mount_path, source_path
    ):
        LOG.warn(f"Found stale bind mount: {ostree_repo_mount_path}, unmounting")
        try:
            sh.umount(ostree_repo_mount_path)
            os.rmdir(ostree_repo_mount_path)
        except Exception:
            LOG.error(f"Failed to fix bind mount at {ostree_repo_mount_path}")
            raise
    # Check for the config file inside the ostree_repo
    check_path = os.path.join(ostree_repo_mount_path, "config")
    if not os.path.exists(check_path):
        LOG.info("Mounting ostree_repo at %s", ostree_repo_mount_path)
        if not os.path.exists(ostree_repo_mount_path):
            os.makedirs(ostree_repo_mount_path, mode=0o755)
        mount_args = (
            "--bind",
            "%s/ostree_repo" % source_path,
            ostree_repo_mount_path,
        )
        try:
            sh.mount(*mount_args)
        except Exception as exc:
            LOG.warn(
                f"Command 'mount {' '.join(mount_args)}' failed; "
                f"attempting to rebuild: {str(exc)}"
            )
            try:
                sh.umount(ostree_repo_mount_path)
            except Exception:
                LOG.exception("rebuild: umount failed, continuing")
            os.rmdir(ostree_repo_mount_path)
            os.makedirs(ostree_repo_mount_path, mode=0o755)
            sh.mount(*mount_args)
