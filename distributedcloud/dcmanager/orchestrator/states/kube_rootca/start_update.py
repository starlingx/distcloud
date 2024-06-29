#
# Copyright (c) 2021, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dccommon.drivers.openstack.sysinv_v1 import KUBE_ROOTCA_UPDATE_ABORTED
from dccommon.drivers.openstack.sysinv_v1 import KUBE_ROOTCA_UPDATE_STARTED

from dcmanager.common.consts import (
    STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
)
from dcmanager.common.consts import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT

from dcmanager.orchestrator.states.base import BaseState


class KubeRootcaUpdateStartState(BaseState):
    """Start a new kube rootca update so that the cert can be uploaded"""

    def __init__(self, region_name):
        super(KubeRootcaUpdateStartState, self).__init__(
            next_state=STRATEGY_STATE_KUBE_ROOTCA_UPDATE_UPLOAD_CERT,
            region_name=region_name,
        )

    def _start_kube_rootca_update(self, strategy_step):
        """Start a kube rootca update

        This is a blocking API call.
        returns the kube rootca update object.
        """
        return self.get_sysinv_client(self.region_name).kube_rootca_update_start(
            force=True, alarm_ignore_list=[]
        )

    def perform_state_action(self, strategy_step):
        """Start the update.

        Any client (sysinv, etc..) should be re-queried whenever used
        to ensure the keystone token is up to date.
        Any exceptions raised by this method set the strategy to FAILED
        Returns the next state for the state machine if successful.
        """
        update = None
        updates = self.get_sysinv_client(self.region_name).get_kube_rootca_updates()
        if len(updates) > 0:
            # There is already an existing kube rootca update in the subcloud
            update = updates[0]
            if update.state == KUBE_ROOTCA_UPDATE_ABORTED:
                # existing update is in aborted state, replace using create
                self.info_log(strategy_step, "Recreating update")
                update = self._start_kube_rootca_update(strategy_step)
            # handle all other states for existing update the same as a new one
        else:
            update = self._start_kube_rootca_update(strategy_step)

        if update.state == KUBE_ROOTCA_UPDATE_STARTED:
            # Update is in started state. Move to default next state
            self.info_log(strategy_step, "Update started")
        else:
            # An unexpected update state. override the next state to use VIM
            self.info_log(strategy_step, "Update in [%s] state." % update.state)
            self.override_next_state(
                STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
            )

        # Success. Move to the next stage
        return self.next_state
