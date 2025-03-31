#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import socket

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import utils as cutils
from dcmanager.common import utils

LOG = logging.getLogger(__name__)

# Default timeout configurations for client reads
CLIENT_READ_TIMEOUT_SECONDS = 60
CLIENT_READ_EXCEPTIONS = (socket.timeout, keystone_exceptions.ServiceUnavailable)
CLIENT_READ_MAX_ATTEMPTS = 2

# Helper functions to retrieve clients for caching


def get_sysinv_client():
    ks_client = get_keystone_client()
    return SysinvClient(
        ks_client.region_name,
        ks_client.session,
        endpoint=ks_client.endpoint_cache.get_endpoint("sysinv"),
        timeout=CLIENT_READ_TIMEOUT_SECONDS,
    )


def get_software_client():
    ks_client = get_keystone_client()
    return SoftwareClient(
        ks_client.session,
        endpoint=ks_client.endpoint_cache.get_endpoint("usm"),
    )


def get_keystone_client(region_name: str = None) -> KeystoneClient:
    """Construct a (cached) keystone client (and token)"""
    if not region_name:
        region_name = cutils.get_region_one_name()

    try:
        os_client = OpenStackDriver(
            region_name=region_name,
            region_clients=None,
            fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
        )
        return os_client.keystone_client
    except Exception:
        LOG.warning("Failure initializing KeystoneClient for region: %s" % region_name)
        raise
