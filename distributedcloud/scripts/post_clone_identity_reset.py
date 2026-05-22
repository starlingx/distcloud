#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Post-clone identity reset for StarlingX nodes.

This script runs as root on the first boot of a freshly cloned
StarlingX node. It is invoked by cloud-init via run-parts and
re-establishes a unique identity for the cloned host before it joins
the distributed cloud.

The script is gated by a sentinel file (CLONE_FLAG_PATH). When the
flag is absent the script exits cleanly (exit code 0), so it is safe
to ship the script on every node and let cloud-init invoke it
unconditionally. When the flag is present the script regenerates the
following identifiers in a fixed order:

    1. sysinv.i_system.uuid (the system UUID in the sysinv DB)
    2. /etc/machine-id
    3. UUID= in /etc/platform/platform.conf (host UUID)
    4. INSTALL_UUID= in /etc/platform/platform.conf and the matching
       /var/www/pages/feed/rel-{sw_version}/install_uuid feed file
    5. OpenStack region name (delegated to update_region_name.py)

On full success the sentinel is removed so subsequent boots are
no-ops. On failure the sentinel is preserved so cloud-init re-invokes
the script on the next boot.
"""

import logging
import os
import subprocess
import sys
import threading

from dc_script_common import get_sw_version
from dc_script_common import PLATFORM_CONF_PATH
from oslo_utils import uuidutils

CLONE_FLAG_PATH = "/etc/platform/.cloned_install"
MACHINE_ID_FILE = "/etc/machine-id"
INSTALL_UUID_FEED_TEMPLATE = "/var/www/pages/feed/rel-{sw_version}/install_uuid"
UPDATE_REGION_SCRIPT_PATH = "/usr/local/bin/update_region_name.py"
REGION_SCRIPT_TIMEOUT = 240  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
LOG = logging.getLogger(__name__)


def update_platform_conf_field(key: str, value: str) -> None:
    """Replace the line beginning with '<key>=' in platform.conf.

    Reads all lines from PLATFORM_CONF_PATH, replaces the first line
    whose lstrip() starts with f"{key}=" with f"{key}={value}\\n",
    then writes all lines back. Raises RuntimeError if no matching
    line is found so the caller can fail loudly.
    """
    prefix = f"{key}="
    with open(PLATFORM_CONF_PATH, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    replaced = False
    for idx, line in enumerate(lines):
        if line.lstrip().startswith(prefix):
            lines[idx] = f"{key}={value}\n"
            replaced = True
            break

    if not replaced:
        raise RuntimeError(f"{key}= not found in {PLATFORM_CONF_PATH}")

    with open(PLATFORM_CONF_PATH, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def update_install_uuid_feed_file(sw_version: str, new_uuid: str) -> None:
    """Rewrite the install_uuid feed file preserving file attributes."""
    path = INSTALL_UUID_FEED_TEMPLATE.format(sw_version=sw_version)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"{new_uuid}\n")


def check_clone_flag() -> bool:
    """Return True if the clone sentinel file exists.

    Reads CLONE_FLAG_PATH via os.path.isfile. A symlink that points
    nowhere returns False. Filesystem errors raise OSError, which the
    caller converts to a non-zero exit.
    """
    return os.path.isfile(CLONE_FLAG_PATH)


def update_sysinv_system_uuid() -> None:
    """Generate a new UUID v4 and UPDATE i_system.uuid in sysinv.

    Raises subprocess.CalledProcessError if psql exits non-zero.
    """
    new_uuid = uuidutils.generate_uuid()
    query = f"UPDATE i_system SET uuid='{new_uuid}';"
    cmd = [
        "su",
        "postgres",
        "-c",
        f'psql --tuples-only -d sysinv -c "{query}"',
    ]
    subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
    )
    LOG.info("System UUID updated to %s.", new_uuid)


def regenerate_machine_id() -> None:
    """Remove /etc/machine-id and re-run systemd-machine-id-setup.

    Raises FileNotFoundError if MACHINE_ID_FILE is missing at removal
    time. Raises subprocess.CalledProcessError if
    systemd-machine-id-setup exits non-zero.
    """
    if not os.path.lexists(MACHINE_ID_FILE):
        raise FileNotFoundError(MACHINE_ID_FILE)
    os.remove(MACHINE_ID_FILE)
    subprocess.run(
        ["systemd-machine-id-setup"],
        check=True,
        capture_output=True,
        text=True,
    )
    LOG.info("Machine ID regenerated.")


def regenerate_host_uuid() -> None:
    """Generate a new host UUID and rewrite UUID= in platform.conf.

    Raises RuntimeError if platform.conf has no UUID= line.
    """
    new_uuid = uuidutils.generate_uuid()
    update_platform_conf_field("UUID", new_uuid)
    LOG.info("Host UUID updated to %s.", new_uuid)


def regenerate_install_uuid() -> None:
    """Generate a new install UUID and update both persistence sites.

    Reads the software version via get_sw_version() to construct the
    install_uuid feed file path. Generates a UUID via
    oslo_utils.uuidutils and persists the new value by rewriting
    the INSTALL_UUID= line in platform.conf via
    update_platform_conf_field, then rewrites the feed file via
    update_install_uuid_feed_file (which preserves the feed file's
    original owner, group, and mode). Returns the newly generated
    UUID string.

    Raises RuntimeError if platform.conf has no INSTALL_UUID= line.
    Raises FileNotFoundError if the feed file is absent.
    """
    sw_version = get_sw_version()
    new_uuid = uuidutils.generate_uuid()
    update_platform_conf_field("INSTALL_UUID", new_uuid)
    update_install_uuid_feed_file(sw_version, new_uuid)
    LOG.info("Install UUID updated to %s.", new_uuid)


def run_update_region_name() -> None:
    """Invoke /usr/local/bin/update_region_name.py with no arguments.

    Runs the existing region-rename helper as a subprocess with
    check=True, capture_output=True, text=True, and a hard timeout
    of REGION_SCRIPT_TIMEOUT seconds. On success the script's stdout
    and stderr are logged at INFO level so operators can audit what
    the helper did. FileNotFoundError, subprocess.CalledProcessError,
    and subprocess.TimeoutExpired are allowed to propagate to the
    caller, which converts them into a non-zero exit code.
    """
    result = subprocess.run(
        [UPDATE_REGION_SCRIPT_PATH],
        check=True,
        capture_output=True,
        text=True,
        timeout=REGION_SCRIPT_TIMEOUT,
    )
    LOG.info("update_region_name.py stdout: %s", result.stdout)
    LOG.info("update_region_name.py stderr: %s", result.stderr)


def remove_clone_flag() -> None:
    """Remove the clone sentinel file at CLONE_FLAG_PATH.

    Calls os.remove(CLONE_FLAG_PATH) so that subsequent boots become
    no-ops. OSError (and its subclasses, e.g. FileNotFoundError or
    PermissionError) is allowed to propagate to the caller, which
    converts it into a non-zero exit. Logs an INFO message on
    successful removal so operators can confirm the script reached
    its terminal step.
    """
    os.remove(CLONE_FLAG_PATH)
    LOG.info("Removed clone flag: %s", CLONE_FLAG_PATH)


def _step_name(fn) -> str:
    """Return the callable's __name__ or a fallback representation."""
    return getattr(fn, "__name__", repr(fn))


def main() -> int:
    """Pipeline orchestrator. Returns the process exit code.

    If the clone flag is absent, return 0 immediately. Otherwise
    run identity regeneration steps concurrently where safe, then
    run region rename and clone flag removal sequentially. Any
    exception is caught, logged at ERROR level with the failing step
    name, and converted into exit code 1 so cloud-init re-invokes
    the script on the next boot.
    """
    try:
        if not check_clone_flag():
            LOG.info("Clone flag not present; nothing to do.")
            return 0
    except OSError as exc:
        LOG.error("Failed to check clone flag: %s", exc)
        return 1

    # update_sysinv_system_uuid and regenerate_machine_id are fully
    # independent. regenerate_host_uuid writes UUID= in platform.conf.
    # regenerate_install_uuid runs later to avoid a race on platform.conf.
    parallel_steps = [
        update_sysinv_system_uuid,
        regenerate_machine_id,
        regenerate_host_uuid,
    ]

    errors = {}
    errors_lock = threading.Lock()

    def _run_step(fn):
        """Thread target that runs a step and captures exceptions."""
        try:
            fn()
        except Exception as exc:  # pylint: disable=broad-except
            with errors_lock:
                errors[_step_name(fn)] = exc

    threads = []
    for fn in parallel_steps:
        name = _step_name(fn)
        LOG.info("Starting step: %s", name)
        thread = threading.Thread(target=_run_step, args=(fn,))
        thread.start()
        threads.append((name, thread))

    for name, thread in threads:
        thread.join()

    if errors:
        for name, exc in errors.items():
            LOG.error("Step '%s' failed: %s", name, exc)
        return 1

    for name, _ in threads:
        LOG.info("Completed step: %s", name)

    sequential_steps = [
        regenerate_install_uuid,
        run_update_region_name,
        remove_clone_flag,
    ]

    for fn in sequential_steps:
        name = _step_name(fn)
        LOG.info("Starting step: %s", name)
        try:
            fn()
        except Exception as exc:  # pylint: disable=broad-except
            LOG.error("Step '%s' failed: %s", name, exc)
            return 1
        LOG.info("Completed step: %s", name)

    LOG.info("Identity reset complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
