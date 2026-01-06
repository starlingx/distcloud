#
# Copyright (c) 2021-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.orchestrator.states.applying_vim_strategy import ApplyingVIMStrategyState


# Max time: 120 minutes = 120 queries x 60 seconds
KUBE_ROOTCA_UPDATE_MAX_WAIT_ATTEMPTS = 120
KUBE_ROOTCA_UPDATE_WAIT_INTERVAL = 60


class ApplyingVIMKubeRootcaUpdateStrategyState(ApplyingVIMStrategyState):
    """State for applying the VIM kube rootca update strategy."""

    def __init__(self, region_name, strategy):
        super(ApplyingVIMKubeRootcaUpdateStrategyState, self).__init__(
            next_state=consts.STRATEGY_STATE_COMPLETE,
            region_name=region_name,
            strategy=strategy,
            strategy_name=vim.STRATEGY_NAME_KUBE_ROOTCA_UPDATE,
            wait_attempts=KUBE_ROOTCA_UPDATE_MAX_WAIT_ATTEMPTS,
            wait_interval=KUBE_ROOTCA_UPDATE_WAIT_INTERVAL,
        )
