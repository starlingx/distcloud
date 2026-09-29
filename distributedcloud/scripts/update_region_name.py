#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Update Openstack region name in an AIO-simplex Non-DC system
#
"""
Usage:
sudo update_region_name.py
"""

import logging
import os
import re
import subprocess
import sys
import time
from typing import Optional

from dc_script_common import get_sw_version
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient import exceptions as ks_exceptions
from keystoneclient.v3 import client as keystone_client
from oslo_utils import uuidutils

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
LOG = logging.getLogger(__name__)

OPENRC_PATH = "/etc/platform/openrc"

PLATFORM_CONF_PATH = "/etc/platform/platform.conf"

REGION_NAME_PATTERN = r"[0-9a-f]{32}"

FILES_TO_UPDATE = [
    OPENRC_PATH,
    "/etc/fm/fm.conf",
    "/etc/nfv/nfv_plugins/nfvi_plugins/config.ini",
    "/etc/barbican/barbican.conf",
    "/etc/mtc.ini",
    "/etc/sysinv/cert-mon.conf",
    "/etc/sysinv/cert-alarm.conf",
    "/etc/sysinv/sysinv.conf",
    "/etc/sysinv/api-paste.ini",
    "/etc/sm-api/sm-api.conf",
    "/etc/software/software.conf",
]

SERVICES_TO_RESTART_SM = [
    "keystone",
    "sysinv-inv",
    "sysinv-conductor",
    "cert-alarm",
    "cert-mon",
    "barbican-api",
    "barbican-worker",
    "barbican-keystone-listener",
    "fm-mgr",
    "vim",
    "vim-api",
]

SERVICES_TO_RESTART_SYSTEMD = [
    "memcached.service",
    "software-agent.service",
    "software-controller-daemon.service",
    "fm-api.service",
]

SERVICES_TO_RESTART_PMON = [
    "sysinv-agent",
    "sm-api",
]

SERVICES_TO_RESTART_MTCE_PMON = [
    "hbsAgent",
    "hbsClient",
    "mtcClient",
]

# pmon-managed processes expose a pidfile. A successful restart is confirmed
# by the pidfile holding a NEW pid (different from the pre-restart pid) that
# corresponds to a live process. This proves the process actually cycled and
# re-read /etc/platform/platform.conf (e.g. the new host UUID), rather than
# merely being "still running".
PMON_PIDFILES = {
    "sysinv-agent": "/var/run/sysinv-agent.pid",
    "sm-api": "/var/run/sm-api.pid",
    "hbsAgent": "/var/run/hbsAgent.pid",
    "hbsClient": "/var/run/hbsClient.pid",
    "mtcClient": "/var/run/mtcClient.pid",
}


def load_credentials() -> dict:
    """Load Keystone credentials by sourcing the openrc file.

    Returns:
        A dict with credential keys suitable for create_keystone_client.
    """
    source_command = f"source {OPENRC_PATH} && env"
    try:
        with subprocess.Popen(
            ["bash", "-c", source_command],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
        ) as proc:
            creds = {}
            for line in proc.stdout:
                if "=" in line:
                    key, _, value = line.partition("=")
                    value = value.strip()
                    if key == "OS_USERNAME":
                        creds["username"] = value
                    elif key == "OS_PASSWORD":
                        creds["password"] = value
                    elif key == "OS_PROJECT_NAME":
                        creds["project_name"] = value
                    elif key == "OS_AUTH_URL":
                        creds["auth_url"] = value
                    elif key == "OS_REGION_NAME":
                        creds["region_name"] = value
                    elif key == "OS_USER_DOMAIN_NAME":
                        creds["user_domain_name"] = value
                    elif key == "OS_PROJECT_DOMAIN_NAME":
                        creds["project_domain_name"] = value
            proc.communicate()

    except subprocess.SubprocessError as e:
        LOG.critical("Failed to execute source command: %s", e)
        sys.exit(1)

    return creds


def create_keystone_client(creds: dict) -> keystone_client.Client:
    """Create a Keystone client using the provided credentials."""
    auth = v3.Password(
        auth_url=creds.get("auth_url"),
        username=creds.get("username"),
        password=creds.get("password"),
        project_name=creds.get("project_name"),
        user_domain_name=creds.get("user_domain_name", "Default"),
        project_domain_name=creds.get("project_domain_name", "Default"),
    )
    keystone_session = session.Session(auth=auth)
    return keystone_client.Client(session=keystone_session, interface="internal")


def read_pmon_pid(service: str):
    """Return the integer pid from a pmon service's pidfile, or None.

    Returns None for a transient read failure (pidfile temporarily
    missing or not yet holding a parseable pid), so callers such as
    verify_pmon_services can retry and eventually fail with a clear
    timeout error if it never appears.
    """
    pidfile = PMON_PIDFILES[service]
    try:
        with open(pidfile, "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        # OSError: pidfile is missing or unreadable (e.g. the daemon has
        # not recreated it yet mid-restart). ValueError: the file exists
        # but does not yet hold a parseable integer pid. Both are treated
        # as "not ready" so the caller can retry.
        return None


def pid_is_alive(pid: Optional[int]) -> bool:
    """Return True if a process with the given pid currently exists.

    Uses the /proc filesystem for a read-only existence check. The
    presence of /proc/<pid> does not depend on process ownership, so
    this correctly reports root-owned daemons as alive regardless of
    the caller's privileges.
    """
    if not pid:
        return False
    return os.path.exists(f"/proc/{pid}")


def restart_pmon_managed_services(service_list: list[str]):
    """Restart pmon-managed services and verify they cycled.

    Captures each service's pid BEFORE issuing pmon-restart, then
    verifies via verify_pmon_services() that the process actually cycled
    (new pid) rather than returning while the old, pre-restart process is
    still draining in-flight work.
    """
    old_pids = {service: read_pmon_pid(service) for service in service_list}
    LOG.info(
        "Issuing pmon-restart for: %s",
        ", ".join(service_list),
    )
    for service in service_list:
        try:
            subprocess.run(
                ["pmon-restart", service],
                capture_output=True,
                text=True,
                check=True,
            )
            LOG.info("Successfully commanded '%s' to restart.", service)
        except subprocess.CalledProcessError as e:
            LOG.error(
                "Failed to restart '%s'. Stderr: %s",
                service,
                e.stderr.strip(),
            )
            sys.exit(1)

    verify_pmon_services(old_pids)


def _pmon_service_restarted(service: str, old_pid) -> bool:
    """Return True once a pmon service holds a new, live pid.

    A pidfile that is temporarily missing after the restart is treated
    as "not restarted yet" so the caller retries.
    """
    new_pid = read_pmon_pid(service)
    if new_pid and new_pid != old_pid and pid_is_alive(new_pid):
        LOG.info(
            "Service '%s' confirmed restarted (new pid=%s).",
            service,
            new_pid,
        )
        return True
    return False


def verify_pmon_services(old_pids, max_retries=10, delay_seconds=5):
    """Verify pmon-managed services actually restarted, with retries.

    All services are polled concurrently each round.

    For each service, poll its pidfile until it holds a NEW pid (different
    from the pre-restart pid captured by restart_pmon_managed_services) that
    corresponds to a live process. This guarantees the process cycled and
    re-read /etc/platform/platform.conf before we proceed. Without this
    barrier, the old process (e.g. sysinv-agent) can keep running with a
    stale in-memory host UUID and mishandle callbacks triggered by later
    steps such as the OAM reconfiguration.

    A pidfile that is temporarily missing after the restart is treated
    as "not restarted yet" and retried; if it never appears with a new
    live pid the verification fails with a timeout error.
    """
    _verify_services(
        list(old_pids),
        lambda service: _pmon_service_restarted(service, old_pids[service]),
        max_retries,
        delay_seconds,
    )


def restart_mtce_services():
    """Force a full restart of the mtce daemons and verify them.

    Restarts mtc-agent (SM-managed) and the pmon-managed heartbeat
    daemons, then verifies they are active. The pmon daemons have their
    pre-restart pids captured first so verify_pmon_services can confirm
    the processes actually cycled.
    """
    LOG.info("Issuing restart command for mtce service")
    mtce_pmon_old_pids = {
        service: read_pmon_pid(service) for service in SERVICES_TO_RESTART_MTCE_PMON
    }
    try:
        subprocess.run(
            ["sm-restart-safe", "service", "mtc-agent"],
            capture_output=True,
            text=True,
            check=True,
        )
        for service in SERVICES_TO_RESTART_MTCE_PMON:
            subprocess.run(
                ["pmon-restart", service],
                capture_output=True,
                text=True,
                check=True,
            )
        LOG.info("Successfully commanded mtce to restart.")
    except subprocess.CalledProcessError as e:
        LOG.error(
            "Failed to restart mtce service. Stderr: %s",
            e.stderr.strip(),
        )
        sys.exit(1)

    verify_sm_services(["mtc-agent"])
    verify_pmon_services(mtce_pmon_old_pids)


def restart_services_sm(service_list: list[str]):
    """Restart SM-managed services and verify they are active."""
    LOG.info("Preparing to restart services: %s", ", ".join(service_list))
    for service in service_list:
        LOG.info("Issuing restart command for service: %s", service)
        try:
            subprocess.run(
                ["sm-restart-safe", "service", service],
                capture_output=True,
                text=True,
                check=True,
            )
            LOG.info("Successfully commanded '%s' to restart.", service)
        except subprocess.CalledProcessError as e:
            LOG.error(
                "Failed to restart service '%s'. Stderr: %s",
                service,
                e.stderr.strip(),
            )
            sys.exit(1)

    verify_sm_services(service_list)


def restart_services_systemd(service_list: list[str]):
    """Restart systemd services and verify they are active.

    Args:
        service_list: A list of systemd service names to restart.
    """
    LOG.info(
        "Preparing to restart systemd services: %s",
        ", ".join(service_list),
    )
    for service in service_list:
        LOG.info("Issuing restart command for systemd service: %s", service)
        try:
            subprocess.run(
                ["systemctl", "restart", service],
                capture_output=True,
                text=True,
                check=True,
            )
            LOG.info("Successfully restarted systemd service '%s'.", service)
        except subprocess.CalledProcessError as e:
            LOG.error(
                "Failed to restart systemd service '%s'. Stderr: %s",
                service,
                e.stderr.strip(),
            )
            sys.exit(1)

    verify_systemd_services(service_list)


def _verify_services(
    service_list: list,
    is_ready,
    max_retries: int,
    delay_seconds: int,
):
    """Poll a group of services until each becomes ready, or fail.

    Instead of confirming one service before starting the next, every
    round checks all services still pending and drops the ones that are
    now ready. A single delay is shared by the whole group per round, so
    the worst-case wait is roughly one timeout window for the group
    rather than one per service.

    Args:
        service_list: Services to verify.
        is_ready: Callable(service) -> bool, True once the service is
            confirmed ready.
        max_retries: Maximum number of polling rounds.
        delay_seconds: Seconds to wait between rounds.
    """
    pending = list(service_list)
    for attempt in range(1, max_retries + 1):
        pending = [service for service in pending if not is_ready(service)]
        if not pending:
            return
        if attempt < max_retries:
            LOG.info(
                "Attempt %d/%d: services not ready yet: %s. Retrying in %ds...",
                attempt,
                max_retries,
                ", ".join(str(s) for s in pending),
                delay_seconds,
            )
            time.sleep(delay_seconds)

    error_msg = (
        f"Services did not become ready after {max_retries} attempts: "
        f"{', '.join(str(s) for s in pending)}."
    )
    LOG.error(error_msg)
    sys.exit(1)


def _sm_service_is_active(service: str) -> bool:
    """Return True if an SM service reports 'enabled-active'."""
    try:
        result = subprocess.run(
            ["sm-query", "service", service],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        LOG.warning(
            "Verification command failed for '%s'. Error: %s",
            service,
            e.stderr.strip(),
        )
        return False
    if "enabled-active" in result.stdout:
        LOG.info("Service '%s' is confirmed enabled-active.", service)
        return True
    return False


def verify_sm_services(service_list, max_retries=10, delay_seconds=5):
    """Verify SM services are 'enabled-active', polling concurrently."""
    _verify_services(service_list, _sm_service_is_active, max_retries, delay_seconds)


def _systemd_service_is_active(service: str) -> bool:
    """Return True if a systemd service reports 'active'."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        LOG.warning(
            "Verification command failed for systemd service '%s'. Error: %s",
            service,
            e.stderr.strip(),
        )
        return False
    if result.stdout.strip() == "active":
        LOG.info("Systemd service '%s' is confirmed active.", service)
        return True
    return False


def verify_systemd_services(service_list, max_retries=10, delay_seconds=5):
    """Verify systemd services are active, polling concurrently."""
    _verify_services(
        service_list, _systemd_service_is_active, max_retries, delay_seconds
    )


def update_sysinv_database(new_region):
    """Update sysinv DB i_system table with new region name."""
    query = f"UPDATE i_system SET region_name='{new_region}';"
    command = ["su", "postgres", "-c", f'psql -d sysinv -c "{query}"']

    try:
        LOG.info("Executing DB query: %s", query)
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        LOG.info("Query result: %s", result.stdout.strip())

    except subprocess.CalledProcessError as e:
        LOG.error("Failed to execute DB query. Error: %s", e.stderr.strip())
        sys.exit(1)


def create_keystone_region(
    keystone: keystone_client.Client,
    new_region_name: str,
):
    """Create the new region in Keystone (idempotent).

    Only creates the region. Does not modify endpoints or delete
    old regions. This is safe to call before updating config files
    since it does not break existing auth.
    """
    try:
        LOG.info("Creating new region '%s' in Keystone...", new_region_name)
        try:
            keystone.regions.create(id=new_region_name)
        except ks_exceptions.Conflict:
            LOG.info(
                "Region '%s' already exists. Skipping creation.",
                new_region_name,
            )
    except ks_exceptions.ClientException as e:
        LOG.error("Keystone API error creating region: %s", e)
        sys.exit(1)


def migrate_keystone_endpoints(
    keystone: keystone_client.Client,
    new_region_name: str,
):
    """Migrate all endpoints to new region and delete stale regions.

    This should be called AFTER config files (including openrc) are
    updated, so that if this step fails, a retry can still
    authenticate using the old region in openrc.

    This function is idempotent:
    - Endpoints already on new region are skipped.
    - Regions that are already deleted get NotFound (skipped).
    """
    try:
        # Update all endpoints not yet on the new region.
        all_endpoints = keystone.endpoints.list()
        for ep in all_endpoints:
            if ep.region == new_region_name:
                continue
            LOG.info(
                "Updating endpoint %s (region %s -> %s): %s",
                ep.id,
                ep.region,
                new_region_name,
                ep.url,
            )
            keystone.endpoints.update(
                ep.id,
                region=new_region_name,
                url=ep.url,
                interface=ep.interface,
                service=ep.service_id,
            )

        # Delete all other regions (only the new one should remain).
        all_regions = keystone.regions.list()
        for region in all_regions:
            if region.id == new_region_name:
                continue
            LOG.info("Deleting stale region: %s", region.id)
            try:
                keystone.regions.delete(region.id)
            except ks_exceptions.NotFound:
                LOG.info("Region '%s' already gone.", region.id)
    except ks_exceptions.ClientException as e:
        LOG.error("Keystone API error during endpoint migration: %s", e)
        sys.exit(1)


def update_files(new_region, file_list):
    """Replace region UUID in config files using regex pattern matching"""
    # Match any key containing "region" (case-insensitive, letters,
    # digits, underscores, colons allowed in key),
    # followed by = or : with optional whitespace, then a 32-char
    # lowercase hex UUID.
    pattern = re.compile(
        r"(?P<key>[\w:]*region[\w:]*)"
        + r"(?P<sep>\s*[=:]\s*)"
        + r"(?P<val>"
        + REGION_NAME_PATTERN
        + r")\b",
        re.IGNORECASE,
    )

    failed_files = []

    for filepath in file_list:
        try:
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()

            new_content, count = pattern.subn(r"\g<key>\g<sep>" + new_region, content)

            if count > 0:
                with open(filepath, "w", encoding="utf-8") as file:
                    file.write(new_content)
                LOG.info(
                    "Updated %d region occurrence(s) in: %s",
                    count,
                    filepath,
                )
            else:
                LOG.info(
                    "No region pattern found in %s. File may already be updated.",
                    filepath,
                )

        except IOError as e:
            LOG.error("Failed to read/write file %s: %s", filepath, e)
            failed_files.append(filepath)

    if failed_files:
        LOG.error(
            "The following files failed to update:\n  %s\n"
            "Fix the above file(s) and re-run this script.",
            "\n  ".join(failed_files),
        )
        sys.exit(1)


def restart_services(sm_services: list[str]):
    """Restart all necessary services.

    Each restart_* helper restarts its own services and verifies they
    are active before returning, so this function is just the ordered
    sequence of restarts.
    """
    restart_services_sm(sm_services)
    restart_services_systemd(SERVICES_TO_RESTART_SYSTEMD)
    restart_mtce_services()
    restart_pmon_managed_services(SERVICES_TO_RESTART_PMON)


def get_versioned_files(sw_version: str) -> list[str]:
    """Return version-dependent file paths to update."""
    return [
        f"/opt/platform/puppet/{sw_version}/hieradata/system.yaml",
        f"/opt/platform/puppet/{sw_version}/hieradata/static.yaml",
        f"/opt/platform/sysinv/{sw_version}/sysinv.conf.default",
    ]


def main():
    """Entry point for the region name migration script."""
    new_region_name = uuidutils.generate_uuid().replace("-", "")
    LOG.info("Generated new region name: %s", new_region_name)

    try:
        sw_version = get_sw_version()
    except RuntimeError as e:
        LOG.critical("%s", e)
        sys.exit(1)
    all_files = FILES_TO_UPDATE + get_versioned_files(sw_version)
    sm_services = list(SERVICES_TO_RESTART_SM)

    LOG.info("--- Starting Migration Script ---")
    LOG.info("Target region: %s", new_region_name)

    creds = load_credentials()
    keystone = create_keystone_client(creds)
    create_keystone_region(keystone, new_region_name)
    update_sysinv_database(new_region_name)
    update_files(new_region_name, all_files)
    migrate_keystone_endpoints(keystone, new_region_name)
    restart_services(sm_services)
    LOG.info("--- Migration Script Completed ---")


if __name__ == "__main__":
    main()
