#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.applying_vim_strategy \
    import ApplyingVIMStrategyState


class ApplyingVIMKubeRootcaUpdateStrategyState(ApplyingVIMStrategyState):
    """State for applying the VIM kube rootca update strategy."""

    def __init__(self, region_name):
        super(ApplyingVIMKubeRootcaUpdateStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_KUBE_ROOTCA_UPDATE)
