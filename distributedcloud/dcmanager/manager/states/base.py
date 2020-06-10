#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import abc
import six

from oslo_log import log as logging

from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dcmanager.common import consts

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseState(object):

    def __init__(self):
        super(BaseState, self).__init__()

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

    @staticmethod
    def get_sysinv_client(region_name, session):
        """construct a sysinv client

           todo(abailey): determine if this client can be cached
        """
        return SysinvClient(region_name, session)

    @abc.abstractmethod
    def perform_state_action(self, strategy_step):
        """Perform the action for this state on the strategy_step"""
        pass
