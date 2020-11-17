#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.creating_vim_strategy \
    import CreatingVIMStrategyState


class CreatingVIMPatchStrategyState(CreatingVIMStrategyState):
    """State for creating the VIM patch strategy prior to kube upgrade."""

    def __init__(self, region_name):
        next_state = consts.STRATEGY_STATE_KUBE_APPLYING_VIM_PATCH_STRATEGY
        super(CreatingVIMPatchStrategyState, self).__init__(
            next_state=next_state,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_SW_PATCH)
        self.SKIP_REASON = "no software patches need to be applied"
        self.SKIP_STATE = \
            consts.STRATEGY_STATE_KUBE_DELETING_VIM_PATCH_STRATEGY

    def skip_check(self, strategy_step, subcloud_strategy):
        """Check if the vim strategy does not need to be built.

        If the vim_strategy that was constructed returns a failure, and
        the reason for the failure is expected, the state machine can skip
        past this vim strategy create/apply and simply delete and move on.

        That happens when the subcloud is already considered up-to-date for
        its patches based on what the vim calculates for the applies patches

        This method will skip if "no software patches need to be applied'
        """

        if subcloud_strategy is not None:
            if subcloud_strategy.state == vim.STATE_BUILD_FAILED:
                if subcloud_strategy.build_phase.reason == self.SKIP_REASON:
                    self.info_log(strategy_step,
                                  "Skip forward in state machine due to:(%s)"
                                  % subcloud_strategy.build_phase.reason)
                    return self.SKIP_STATE
        # If we get here, there is not a reason to skip
        return None
