#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from oslo_log import log as logging

from dcmanager.manager.states.base import BaseState

LOG = logging.getLogger(__name__)


class CompletingState(BaseState):
    """Upgrade state actions for completing an upgrade"""

    def __init__(self):
        super(CompletingState, self).__init__()

    def perform_state_action(self, strategy_step):
        """Complete an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """
        LOG.warning("CompletingState has not been implemented yet.")

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        LOG.warning("Faking transition to next state")
        return True
