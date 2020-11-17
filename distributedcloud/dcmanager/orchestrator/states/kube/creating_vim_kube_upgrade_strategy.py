#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import utils as dcmanager_utils
from dcmanager.orchestrator.states.creating_vim_strategy \
    import CreatingVIMStrategyState


class CreatingVIMKubeUpgradeStrategyState(CreatingVIMStrategyState):
    """State for creating the VIM upgrade strategy."""

    def __init__(self, region_name):
        next_state = \
            consts.STRATEGY_STATE_KUBE_APPLYING_VIM_KUBE_UPGRADE_STRATEGY
        super(CreatingVIMKubeUpgradeStrategyState, self).__init__(
            next_state=next_state,
            region_name=region_name,
            strategy_name=vim.STRATEGY_NAME_KUBE_UPGRADE)

    def get_target_kube_version(self, strategy_step):
        kube_versions = self.get_sysinv_client(
            consts.DEFAULT_REGION_NAME).get_kube_versions()
        active_kube_version = dcmanager_utils.get_active_kube_version(
            kube_versions)
        if active_kube_version is None:
            message = "Active kube version in RegionOne not found"
            self.warn_log(strategy_step, message)
            raise Exception(message)
        return active_kube_version

    def _create_vim_strategy(self, strategy_step, region):
        self.info_log(strategy_step,
                      "Creating (%s) VIM strategy" % self.strategy_name)

        # determine the target for the vim kube strategy
        active_kube_version = self.get_target_kube_version(strategy_step)

        # Get the update options
        opts_dict = dcmanager_utils.get_sw_update_opts(
            self.context,
            for_sw_update=True,
            subcloud_id=strategy_step.subcloud_id)

        # Call the API to build the VIM strategy
        subcloud_strategy = self.get_vim_client(region).create_strategy(
            self.strategy_name,
            opts_dict['storage-apply-type'],
            opts_dict['worker-apply-type'],
            opts_dict['max-parallel-workers'],
            opts_dict['default-instance-action'],
            opts_dict['alarm-restriction-type'],
            to_version=active_kube_version)

        # a successful API call to create MUST set the state be 'building'
        if subcloud_strategy.state != vim.STATE_BUILDING:
            raise Exception("Unexpected VIM strategy build state: %s"
                            % subcloud_strategy.state)
        return subcloud_strategy
