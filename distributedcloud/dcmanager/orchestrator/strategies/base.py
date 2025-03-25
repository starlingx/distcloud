# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import abc

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.drivers.openstack import vim
from dcmanager.common import context
from dcmanager.common import utils

LOG = logging.getLogger(__name__)


class BaseStrategy(object):
    """Base strategy

    This class is responsible specifying common methods used by strategies during
    their orchestration.
    """

    # each subclass must provide the STATE_OPERATORS
    STATE_OPERATORS = {}

    def __init__(
        self,
        audit_rpc_client,
        update_type,
        vim_strategy_name,
        starting_state,
    ):
        # Context object for RPC queries
        self.context = context.get_admin_context()
        # Used to notify dcmanager-audit to trigger an audit
        self.audit_rpc_client = audit_rpc_client
        # The update type for the orch thread
        self.update_type = update_type
        # The vim strategy name for the orch thread
        self.vim_strategy_name = vim_strategy_name
        # When an apply is initiated, this is the first state
        self.starting_state = starting_state
        # Track if the strategy setup function was executed
        self._setup = False

    @abc.abstractmethod
    def trigger_audit(self):
        """Subclass MUST override this method"""
        LOG.warn(
            "(%s) BaseStrategy subclass must override trigger_audit" % self.update_type
        )

    def _pre_apply_setup(self):
        """Setup performed once before a strategy starts to apply"""
        if not self._setup:
            LOG.info("(%s) BaseStrategy Pre-Apply Setup" % self.update_type)
            self._setup = True
            self.pre_apply_setup()

    def pre_apply_setup(self):
        """Subclass can override this method"""

    def _post_delete_teardown(self):
        """Cleanup code executed once after deleting a strategy"""
        if self._setup:
            LOG.info("(%s) BaseStrategy Post-Delete Teardown" % self.update_type)
            self._setup = False
            self.post_delete_teardown()

    def post_delete_teardown(self):
        """Subclass can override this method"""

    @staticmethod
    def get_ks_client(region_name=dccommon_consts.DEFAULT_REGION_NAME):
        """This will get a cached keystone client (and token)

        throws an exception if keystone client cannot be initialized
        """
        os_client = OpenStackDriver(
            region_name=region_name,
            region_clients=None,
            fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
        )
        return os_client.keystone_client

    @staticmethod
    def get_vim_client(region_name=dccommon_consts.DEFAULT_REGION_NAME):
        ks_client = BaseStrategy.get_ks_client(region_name)
        return vim.VimClient(region_name, ks_client.session)

    @staticmethod
    def get_sysinv_client(region_name=dccommon_consts.DEFAULT_REGION_NAME):
        ks_client = BaseStrategy.get_ks_client(region_name)
        endpoint = ks_client.endpoint_cache.get_endpoint("sysinv")
        return SysinvClient(region_name, ks_client.session, endpoint=endpoint)

    @staticmethod
    def get_software_client(region_name=dccommon_consts.DEFAULT_REGION_NAME):
        ks_client = BaseStrategy.get_ks_client(region_name)
        return SoftwareClient(
            ks_client.session,
            endpoint=ks_client.endpoint_cache.get_endpoint("usm"),
        )

    @staticmethod
    def get_patching_client(region_name=dccommon_consts.DEFAULT_REGION_NAME):
        ks_client = BaseStrategy.get_ks_client(region_name)
        return PatchingClient(region_name, ks_client.session)

    def determine_state_operator(self, region_name, strategy_step):
        """Return the state operator for the current state"""

        state_operator = self.STATE_OPERATORS.get(strategy_step.state)
        # instantiate and return the state_operator class
        return state_operator(region_name=region_name)
