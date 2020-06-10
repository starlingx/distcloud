#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.manager.states.base import BaseState


class StartingUpgradeState(BaseState):
    """Upgrade state for starting an upgrade on a subcloud"""

    def __init__(self, force=False):
        super(StartingUpgradeState, self).__init__()
        self.force = force

    def perform_state_action(self, strategy_step):
        """Start an upgrade on a subcloud

        Any exceptions raised by this method set the strategy to FAILED
        Returning normally from this method set the strategy to the next step
        """
        # get the keystone and sysinv clients for the subcloud
        ks_client = self.get_keystone_client(strategy_step.subcloud.name)
        sysinv_client = self.get_sysinv_client(strategy_step.subcloud.name,
                                               ks_client.session)

        # Check if an existing upgrade is already in progress.
        # The list of upgrades will never contain more than one entry.
        upgrades = sysinv_client.get_upgrades()
        if upgrades is not None and len(upgrades) > 0:
            for upgrade in upgrades:
                # If a previous upgrade exists (even one that failed) skip
                self.info_log(strategy_step,
                              "An upgrade already exists: %s" % upgrade)
        else:
            # invoke the API 'upgrade-start'.
            # This call is synchronous and throws an exception on failure.
            sysinv_client.upgrade_start(self.force)

        # When we return from this method without throwing an exception, the
        # state machine can proceed to the next state
        return True
