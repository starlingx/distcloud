#
# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.consts import DEFAULT_REGION_NAME
from dcmanager.common.consts import STRATEGY_STATE_COMPLETE
from dcmanager.common.consts \
    import STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY
from dcmanager.common import utils
from dcmanager.orchestrator.states.base import BaseState


class KubeUpgradePreCheckState(BaseState):
    """Perform pre check operations to determine if kube upgrade is required"""

    def __init__(self, region_name):
        super(KubeUpgradePreCheckState, self).__init__(
            next_state=STRATEGY_STATE_KUBE_CREATING_VIM_KUBE_UPGRADE_STRATEGY,
            region_name=region_name)

    def perform_state_action(self, strategy_step):
        """This state will determine the starting state for kube upgrade

        A subcloud will be out-of-sync if its version does not match the
        system controller version, however it may be a higher version.

        Subclouds at a higher version than the to-version will be skipped.

        If the strategy contains the extra_args: 'to-version',
        the subcloud can be upgraded if the 'available' version is
        less than or equal to that version.

        If a subcloud has an upgrade in progress, its to-version is compared
        rather than the 'available' version in the subcloud.  This allows
        a partially upgraded subcloud to be skipped.
        """
        # Get any  existing kubernetes upgrade operation in the subcloud,
        # and use its to-version rather than the 'available' version for
        # determining whether or not to skip.
        subcloud_kube_upgrades =  \
            self.get_sysinv_client(self.region_name).get_kube_upgrades()
        if len(subcloud_kube_upgrades) > 0:
            target_version = subcloud_kube_upgrades[0].to_version
            self.debug_log(strategy_step,
                           "Pre-Check. Existing Kubernetes upgrade:(%s) exists"
                           % target_version)
        else:
            # The subcloud can only be upgraded to an 'available' version
            subcloud_kube_versions = \
                self.get_sysinv_client(self.region_name).get_kube_versions()
            target_version = \
                utils.get_available_kube_version(subcloud_kube_versions)
            self.debug_log(strategy_step,
                           "Pre-Check. Available Kubernetes upgrade:(%s)"
                           % target_version)

        # check extra_args for the strategy
        # if there is a to-version, use that when checking against the subcloud
        # target version, otherwise compare to the sytem controller version
        # to determine if this subcloud is permitted to upgrade.
        extra_args = utils.get_sw_update_strategy_extra_args(self.context)
        if extra_args is None:
            extra_args = {}
        to_version = extra_args.get('to-version', None)
        if to_version is None:
            sys_kube_versions = \
                self.get_sysinv_client(DEFAULT_REGION_NAME).get_kube_versions()
            to_version = utils.get_active_kube_version(sys_kube_versions)
            if to_version is None:
                # No active target kube version on the system controller means
                # the system controller is part-way through a kube upgrade
                message = "System Controller has no active target kube version"
                self.warn_log(strategy_step, message)
                raise Exception(message)

        # For the to-version, the code currently allows a partial version
        # ie: v1.20  or a version that is much higher than is installed.
        # This allows flexability when passing in a to-version.

        # The 'to-version' is the desired version to upgrade the subcloud.
        # The 'target_version' is what the subcloud is allowed to upgrade to.
        # if the 'target_version' is already greater than the 'to-version' then
        # we want to skip this subcloud.
        #
        # Example: subcloud 'target_version' is 1.20.9 , to-version is 1.19.13
        # so the upgrade should be skipped.
        #
        # Example2: subcloud 'target_version' is 1.19.13, to-version is 1.20.9
        # so the upgrade should be invoked, but will only move to 1.19.13.
        # Another upgrade would be needed for the versions to match.
        #
        # Example3: subcloud 'target_version': None. The upgrade is skipped.
        # The subcloud is already upgraded as far as it can go/

        should_skip = False
        if target_version is None:
            should_skip = True
        else:
            # -1 if target_version is less. 0 means equal. 1 means greater
            # Should skip is the target_version is already greater
            if 1 == utils.kube_version_compare(target_version, to_version):
                should_skip = True

        # the default next state is to create the vim strategy
        # if there is no need to upgrade, short circuit to complete.
        if should_skip:
            # Add a log indicating we are skipping (and why)
            self.override_next_state(STRATEGY_STATE_COMPLETE)
            self.info_log(strategy_step,
                          "Pre-Check Skip. Orchestration To-Version:(%s). "
                          "Subcloud To-Version:(%s)"
                          % (to_version, target_version))
        else:
            # Add a log indicating what we expect the next state to 'target'
            self.info_log(strategy_step,
                          "Pre-Check Pass. Orchestration To-Version:(%s). "
                          " Subcloud To-Version:(%s)"
                          % (to_version, target_version))
        return self.next_state
