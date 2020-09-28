#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import abc
import six

from oslo_log import log as logging

from dccommon.drivers.openstack.barbican import BarbicanClient
from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon.drivers.openstack.vim import VimClient
from dcmanager.common import consts
from dcmanager.common import context

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseState(object):

    def __init__(self, next_state, region_name):
        super(BaseState, self).__init__()
        self.next_state = next_state
        self.context = context.get_admin_context()
        self._stop = None
        self.region_name = region_name

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
        LOG.debug("Stage: %s, State: %s, Subcloud: %s, Details: %s"
                  % (strategy_step.stage,
                     strategy_step.state,
                     self.get_region_name(strategy_step),
                     details))

    def info_log(self, strategy_step, details):
        LOG.info("Stage: %s, State: %s, Subcloud: %s, Details: %s"
                 % (strategy_step.stage,
                    strategy_step.state,
                    self.get_region_name(strategy_step),
                    details))

    def warn_log(self, strategy_step, details):
        LOG.warn("Stage: %s, State: %s, Subcloud: %s, Details: %s"
                 % (strategy_step.stage,
                    strategy_step.state,
                    self.get_region_name(strategy_step),
                    details))

    def error_log(self, strategy_step, details):
        LOG.error("Stage: %s, State: %s, Subcloud: %s, Details: %s"
                  % (strategy_step.stage,
                     strategy_step.state,
                     self.get_region_name(strategy_step),
                     details))

    @staticmethod
    def get_region_name(strategy_step):
        """Get the region name for a strategy step"""
        if strategy_step.subcloud_id is None:
            # This is the SystemController.
            return consts.DEFAULT_REGION_NAME
        return strategy_step.subcloud.name

    @staticmethod
    def get_keystone_client(region_name=consts.DEFAULT_REGION_NAME):
        """Construct a (cached) keystone client (and token)"""

        try:
            os_client = OpenStackDriver(region_name=region_name,
                                        region_clients=None)
            return os_client.keystone_client
        except Exception:
            LOG.warning('Failure initializing KeystoneClient for region: %s'
                        % region_name)
            raise

    def get_sysinv_client(self, region_name):
        """construct a sysinv client

           todo(abailey): determine if this client can be cached
        """
        keystone_client = self.get_keystone_client(region_name)

        return SysinvClient(region_name, keystone_client.session)

    def get_patching_client(self, region_name=consts.DEFAULT_REGION_NAME):
        keystone_client = self.get_keystone_client(region_name)
        return PatchingClient(region_name, keystone_client.session)

    @property
    def local_sysinv(self):
        return self.get_sysinv_client(consts.DEFAULT_REGION_NAME)

    @property
    def subcloud_sysinv(self):
        return self.get_sysinv_client(self.region_name)

    def get_barbican_client(self, region_name):
        """construct a barbican client

        """
        keystone_client = self.get_keystone_client(region_name)

        return BarbicanClient(region_name, keystone_client.session)

    def get_vim_client(self, region_name):
        """construct a vim client for a region."""
        keystone_client = self.get_keystone_client(region_name)
        return VimClient(region_name,
                         keystone_client.session)

    @abc.abstractmethod
    def perform_state_action(self, strategy_step):
        """Perform the action for this state on the strategy_step

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """
        pass
