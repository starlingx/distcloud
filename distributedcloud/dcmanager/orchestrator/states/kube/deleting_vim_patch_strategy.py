#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common.exceptions import KubeUpgradeFailedException
from dcmanager.orchestrator.states.base import BaseState


class DeletingVIMPatchStrategyState(BaseState):
    """State to delete vim patch strategy before creating vim kube strategy"""

    def __init__(self, region_name):
        next_state = \
            consts.STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
        super(DeletingVIMPatchStrategyState, self).__init__(
            next_state=next_state,
            region_name=region_name)

    def perform_state_action(self, strategy_step):
        """Delete the VIM patch strategy if it exists.

        Returns the next state in the state machine on success.
        Any exceptions raised by this method set the strategy to FAILED.
        """

        self.info_log(strategy_step, "Delete vim patch strategy if it exists")
        region = self.get_region_name(strategy_step)
        strategy_name = vim.STRATEGY_NAME_SW_PATCH

        vim_strategy = self.get_vim_client(region).get_strategy(
            strategy_name=strategy_name,
            raise_error_if_missing=False)

        # If the vim patch strategy does not exist, there is nothing to delete
        if vim_strategy is None:
            self.info_log(strategy_step, "Skip. No vim patch strategy exists")
        else:
            self.info_log(strategy_step, "Deleting vim patch strategy")
            # The vim patch strategy cannot be deleted in certain states
            if vim_strategy.state in [vim.STATE_BUILDING,
                                      vim.STATE_APPLYING,
                                      vim.STATE_ABORTING]:
                # Can't delete a strategy in these states
                message = ("VIM patch strategy in wrong state:(%s) to delete"
                           % vim_strategy.state)
                raise KubeUpgradeFailedException(
                    subcloud=self.region_name,
                    details=message)
            # delete the vim patch strategy
            self.get_vim_client(region).delete_strategy(
                strategy_name=strategy_name)

        # Success
        return self.next_state
