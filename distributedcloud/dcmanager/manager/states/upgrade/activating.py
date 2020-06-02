#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.manager.states.base import BaseState

ALREADY_ACTIVATING_STATES = ['activation-requested',
                             'activation-failed',
                             'activation-complete',
                             'activating']


class ActivatingUpgradeState(BaseState):
    """Upgrade state actions for activating an upgrade"""

    def __init__(self):
        super(ActivatingUpgradeState, self).__init__()

    def perform_state_action(self, strategy_step):
        """Activate an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """
        # get the keystone and sysinv clients for the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)
        upgrades = sysinv_client.get_upgrades()

        # If there are no existing upgrades, there is nothing to activate
        if len(upgrades) == 0:
            raise Exception("No upgrades were found to activate")

        # The list of upgrades will never contain more than one entry.
        for upgrade in upgrades:
            # Check if an existing upgrade is already activated
            if upgrade.state in ALREADY_ACTIVATING_STATES:
                self.info_log(strategy_step,
                              "Already in activating state:%s" % upgrade.state)
                break
        else:
            # invoke the API 'upgrade-activate'.
            # Throws an exception on failure (no upgrade found, bad host state)
            sysinv_client.upgrade_activate()

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
