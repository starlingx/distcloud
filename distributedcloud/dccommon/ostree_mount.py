# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

from oslo_log import log as logging
import sh

from dccommon import consts
from dcmanager.common import utils

# The 'sh' library is magical - it looks up CLI functions dynamically.
# Disable the pylint warnings here:
# pylint: disable=not-callable,no-member

LOG = logging.getLogger(__name__)


def check_stale_bind_mount(mount_path, source_path):
    """Check if the mount has become stale.

    We do this by comparing the directory inodes. If the bind mount is
    valid, the two directories should have the same inode number; otherwise
    the original directory has been replaced and we are no longer tracking
    the actual location of source_path. In this case we teardown the bind
    mount.
    """
    mount_path_inode = os.stat(mount_path).st_ino
    source_path_inode = os.stat(source_path).st_ino
    if mount_path_inode != source_path_inode:
        failure_prefix = f"Failed to repair bind mount at {mount_path}"
        LOG.error(f"Found stale bind mount: {mount_path}: attempting repair")
        try:
            sh.umount(mount_path)
        except sh.ErrorReturnCode_32:
            # Exit code 32 is "mount failure"
            # Log the exception, but proceed with the rmdir, allowing a
            # remount attempt
            LOG.exception(f"{failure_prefix}: unmount failed (continuing)")
        except Exception:
            LOG.error(f"{failure_prefix}: unexpected umount failure")
            raise
        try:
            os.rmdir(mount_path)
        except Exception:
            LOG.error(f"{failure_prefix}: rmdir failed")
            raise
        return True

    return False


# TODO(kmacleod): utils.synchronized should be moved into dccommon
@utils.synchronized("ostree-mount-subclouds", external=True)
def validate_ostree_iso_mount(software_version):
    """Ensure the ostree_repo is properly mounted under the iso path.

    Validity check includes if the mount is stale.
    If stale, the bind mount is recreated.
    Note that ostree_repo is mounted in a location not specific to a subcloud.
    """
    ostree_repo_mount_path = os.path.join(
        consts.SUBCLOUD_ISO_PATH, software_version, "ostree_repo"
    )
    ostree_repo_source_path = os.path.join(
        consts.SUBCLOUD_FEED_PATH,
        "rel-{version}".format(version=software_version),
        "ostree_repo",
    )
    LOG.debug(
        "Checking ostree_repo mount: %s against %s",
        ostree_repo_mount_path,
        ostree_repo_source_path,
    )
    if os.path.exists(ostree_repo_mount_path):
        check_stale_bind_mount(ostree_repo_mount_path, ostree_repo_source_path)

    # Check for the config file inside the ostree_repo
    check_path = os.path.join(ostree_repo_mount_path, "config")
    if not os.path.exists(check_path):
        LOG.info("Mounting ostree_repo at %s", ostree_repo_mount_path)
        if not os.path.exists(ostree_repo_mount_path):
            os.makedirs(ostree_repo_mount_path, mode=0o755)
        mount_args = (
            "--bind",
            ostree_repo_source_path,
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
