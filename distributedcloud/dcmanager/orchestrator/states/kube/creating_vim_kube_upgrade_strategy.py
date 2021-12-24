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

    def _create_vim_strategy(self, strategy_step, region):
        self.info_log(strategy_step,
                      "Creating (%s) VIM strategy" % self.strategy_name)
        target_kube_version = None

        # If there is an existing kube upgrade object, its to_version is used
        # This is to allow resume for a kube upgrade
        subcloud_kube_upgrades = \
            self.get_sysinv_client(region).get_kube_upgrades()
        if len(subcloud_kube_upgrades) > 0:
            target_kube_version = subcloud_kube_upgrades[0].to_version
        else:
            # Creating a new kube upgrade, rather than resuming.
            # Subcloud can only be upgraded to its available version
            # Pre-Check does rejection logic.
            kube_versions = \
                self.get_sysinv_client(region).get_kube_versions()
            target_kube_version = \
                dcmanager_utils.get_available_kube_version(kube_versions)

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
            to_version=target_kube_version)

        # a successful API call to create MUST set the state be 'building'
        if subcloud_strategy.state != vim.STATE_BUILDING:
            raise Exception("Unexpected VIM strategy build state: %s"
                            % subcloud_strategy.state)
        return subcloud_strategy
