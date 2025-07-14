#
# Copyright (c) 2020-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc
from functools import lru_cache
from typing import Optional
from typing import Type

from oslo_log import log as logging

from dccommon.drivers.openstack.barbican import BarbicanClient
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.keystone_v3 import KeystoneClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.drivers.openstack import vim
from dccommon import utils as cutils
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import utils
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)

# The cache is scoped to the strategy state object, so we only cache clients
# for the subcloud region. This reduces redundant clients and minimizes
# the number of unnecessary TCP connections.
CLIENT_CACHE_SIZE = 1


class BaseState(object, metaclass=abc.ABCMeta):

    def __init__(self, next_state, region_name):
        super(BaseState, self).__init__()
        self.next_state = next_state
        self.context = context.get_admin_context()
        self._stop = None
        self.region_name = region_name
        self._shared_caches = None
        self.extra_args = None
        self.oam_floating_ip_dict = None

    def override_next_state(self, next_state):
        self.next_state = next_state

    def registerStopEvent(self, stop_event):
        """Store an orch_thread threading.Event to detect stop."""
        self._stop = stop_event

    def stopped(self):
        """Check if the threading.Event is set, otherwise return False."""
        if self._stop is not None:
            return self._stop.isSet()
        else:
            return False

    def debug_log(self, strategy_step, details):
        LOG.debug(
            "Stage: %s, State: %s, Subcloud: %s, Details: %s"
            % (
                strategy_step.stage,
                strategy_step.state,
                self.get_subcloud_name(strategy_step),
                details,
            )
        )

    def info_log(self, strategy_step, details):
        LOG.info(
            "Stage: %s, State: %s, Subcloud: %s, Details: %s"
            % (
                strategy_step.stage,
                strategy_step.state,
                self.get_subcloud_name(strategy_step),
                details,
            )
        )

    def warn_log(self, strategy_step, details):
        LOG.warn(
            "Stage: %s, State: %s, Subcloud: %s, Details: %s"
            % (
                strategy_step.stage,
                strategy_step.state,
                self.get_subcloud_name(strategy_step),
                details,
            )
        )

    def error_log(self, strategy_step, details):
        LOG.error(
            "Stage: %s, State: %s, Subcloud: %s, Details: %s"
            % (
                strategy_step.stage,
                strategy_step.state,
                self.get_subcloud_name(strategy_step),
                details,
            )
        )

    def exception_log(self, strategy_step, details):
        LOG.exception(
            "Stage: %s, State: %s, Subcloud: %s, Details: %s"
            % (
                strategy_step.stage,
                strategy_step.state,
                self.get_subcloud_name(strategy_step),
                details,
            )
        )

    def handle_exception(
        self,
        strategy_step,
        details: str,
        raise_exception: Type[exceptions.DCOrchestrationFailedException],
        exc: Optional[Exception] = None,
        state: Optional[str] = None,
        strategy_name: Optional[str] = None,
    ) -> None:
        """Handle exception for DC Orchestration strategies.

        Helper function to log an error, raise a DCOrchestrationFailedException, update
        the subcloud's deploy state and error description.

        :param strategy_step: The current strategy step.
        :param details: The exception details used in the new exception.
        :param raise_exception: The exception class to be raised.
        :param exc: The original exception that was caught (optional).
        :param state: State of the VIM strategy used in the the exception (optional).
        :param strategy_name: The name of the strategy to be passed to the exception
                              (optional).
        """

        # TODO(nicodemos): Change all orchestration exceptions to use handle_exception
        # and remove the logging from orch_thread to avoid duplicate logging.
        if exc:
            log_msg = f"{details} Error: {str(exc)}"
            self.exception_log(strategy_step, log_msg)
        deploy_status = (
            consts.DEPLOY_STATE_DONE
            if strategy_name != vim.STRATEGY_NAME_SW_USM
            else consts.DEPLOY_STATE_SW_DEPLOY_APPLY_STRATEGY_FAILED
        )
        db_api.subcloud_update(
            self.context,
            strategy_step.subcloud_id,
            deploy_status=deploy_status,
            error_description=details,
        )
        raise raise_exception(
            subcloud=strategy_step.subcloud.name,
            details=details,
            strategy_name=strategy_name,
            state=state,
        )

    @staticmethod
    def get_region_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return cutils.get_region_one_name()
        return strategy_step.subcloud.region_name

    @staticmethod
    def get_subcloud_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return cutils.get_region_one_name()
        return strategy_step.subcloud.name

    @staticmethod
    @lru_cache(maxsize=CLIENT_CACHE_SIZE)
    def get_keystone_client(region_name: str = None) -> KeystoneClient:
        """Construct a (cached) keystone client (and token)"""
        if not region_name:
            region_name = cutils.get_region_one_name()

        try:
            return OpenStackDriver(
                region_name=region_name,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
        except Exception:
            LOG.warning(
                f"Failure initializing KeystoneClient for region: {region_name}"
            )
            raise

    @lru_cache(maxsize=CLIENT_CACHE_SIZE)
    def get_sysinv_client(self, region_name: str) -> SysinvClient:
        """Get the Sysinv client for the given region."""
        keystone_client = self.get_keystone_client(region_name)
        endpoint = keystone_client.endpoint_cache.get_endpoint("sysinv")
        return SysinvClient(region_name, keystone_client.session, endpoint=endpoint)

    @lru_cache(maxsize=CLIENT_CACHE_SIZE)
    def get_fm_client(self, region_name: str) -> FmClient:
        """Get the FM client for the given region."""
        keystone_client = self.get_keystone_client(region_name)
        endpoint = keystone_client.endpoint_cache.get_endpoint("fm")
        return FmClient(region_name, keystone_client.session, endpoint=endpoint)

    @lru_cache(maxsize=CLIENT_CACHE_SIZE)
    def get_software_client(self, region_name: str = None) -> SoftwareClient:
        """Get the Software client for the given region."""
        keystone_client = self.get_keystone_client(region_name)
        return SoftwareClient(keystone_client.session, keystone_client.region_name)

    @lru_cache(maxsize=CLIENT_CACHE_SIZE)
    def get_barbican_client(self, region_name: str) -> BarbicanClient:
        """Get the Barbican client for the given region."""
        keystone_client = self.get_keystone_client(region_name)
        return BarbicanClient(region_name, keystone_client.session)

    @lru_cache(maxsize=CLIENT_CACHE_SIZE)
    def get_vim_client(self, region_name: str) -> vim.VimClient:
        """Get the Vim client for the given region."""
        keystone_client = self.get_keystone_client(region_name)
        return vim.VimClient(keystone_client.session, region=region_name)

    @property
    def local_sysinv(self) -> SysinvClient:
        """Return the local Sysinv client."""
        return self.get_sysinv_client(cutils.get_region_one_name())

    @property
    def subcloud_sysinv(self) -> SysinvClient:
        """Return the subcloud Sysinv client."""
        return self.get_sysinv_client(self.region_name)

    def add_extra_args(self, extra_args):
        self.extra_args = extra_args

    def add_oam_floating_ip_dict(self, oam_floating_ip_dict):
        self.oam_floating_ip_dict = oam_floating_ip_dict

    def add_shared_caches(self, shared_caches):
        # Shared caches not required by all states, so instantiate only if necessary
        self._shared_caches = shared_caches

    def _read_from_cache(self, cache_type, **filter_params):
        if self._shared_caches is not None:
            return self._shared_caches.read(cache_type, **filter_params)
        else:
            raise exceptions.InvalidParameterValue(
                err="Specified cache type '%s' not present" % cache_type
            )

    @abc.abstractmethod
    def perform_state_action(self, strategy_step):
        """Perform the action for this state on the strategy_step

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
