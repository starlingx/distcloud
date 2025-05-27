#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from keystoneauth1.exceptions.auth_plugins import AuthPluginException
from keystoneauth1.identity import v3
from keystoneauth1 import session
from oslo_config import cfg
from oslo_log import log

LOG = log.getLogger(__name__)
CONF = cfg.CONF


# TODO(ecandotti): Migrate to EndpointCache
class KeystoneSessionManager(object):
    def __init__(self, auth_section="keystone_authtoken"):
        """Initialize session manager from config section."""
        auth_conf = CONF.get(auth_section)

        auth = v3.Password(
            auth_url=auth_conf.auth_url,
            username=auth_conf.username,
            password=auth_conf.password,
            project_name=auth_conf.project_name,
            user_domain_name=auth_conf.user_domain_name,
            project_domain_name=auth_conf.project_domain_name,
        )

        self.session = session.Session(auth=auth)

    def get_endpoint_url(
        self, service_type, service_name=None, interface="admin", region_name=None
    ):
        return self.session.get_endpoint(
            service_type=service_type,
            service_name=service_name,
            interface=interface,
            region_name=region_name or CONF.get("keystone_authtoken").region_name,
        )

    def get_token(self):
        """Return a valid token."""
        try:
            return self.session.get_token()
        except AuthPluginException as e:
            LOG.exception(f"Failed to get keystone token: {str(e)}")
            raise
