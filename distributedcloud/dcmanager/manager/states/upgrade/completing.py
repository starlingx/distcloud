#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.manager.states.base import BaseState


class CompletingUpgradeState(BaseState):
    """Upgrade state actions for completing an upgrade"""

    def __init__(self):
        super(CompletingUpgradeState, self).__init__()

    def perform_state_action(self, strategy_step):
        """Complete an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """
        # get the keystone and sysinv clients for the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        # upgrade-complete causes the upgrade to be deleted.
        # if no upgrade exists, there is no need to call it.
        # The API should always return a list, but check for None anyways
        upgrades = sysinv_client.get_upgrades()
        if len(upgrades) == 0:
            self.info_log(strategy_step,
                          "No upgrades exist. Nothing needs completing")
            return True

        # invoke the API 'upgrade-complete'
        # This is a blocking call that raises an exception on failure.
        sysinv_client.upgrade_complete()

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
