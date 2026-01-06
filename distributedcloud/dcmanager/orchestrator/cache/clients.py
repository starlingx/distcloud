#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import socket

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.endpoint_cache import EndpointCache
from dccommon import utils as cutils

LOG = logging.getLogger(__name__)

# Default timeout configurations for client reads
CLIENT_READ_TIMEOUT_SECONDS = 60
CLIENT_READ_EXCEPTIONS = (socket.timeout, keystone_exceptions.ServiceUnavailable)
CLIENT_READ_MAX_ATTEMPTS = 2

# Helper functions to retrieve clients for caching


def get_sysinv_client():
    admin_session = EndpointCache.get_admin_session()
    region_name = cutils.get_region_one_name()
    return SysinvClient(
        region_name,
        admin_session,
        timeout=CLIENT_READ_TIMEOUT_SECONDS,
    )


def get_software_client():
    admin_session = EndpointCache.get_admin_session()
    region_name = cutils.get_region_one_name()
    return SoftwareClient(
        admin_session,
        region=region_name,
    )
