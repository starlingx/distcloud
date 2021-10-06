#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common.consts \
    import STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY
from dcmanager.common.consts \
    import STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START
from dcmanager.common import utils as dcmanager_utils
from dcmanager.orchestrator.states.base import BaseState


class KubeRootcaUpdatePreCheckState(BaseState):
    """Perform pre check operations to determine if cert upload is required"""

    def __init__(self, region_name):
        super(KubeRootcaUpdatePreCheckState, self).__init__(
            next_state=STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
            region_name=region_name)

    def perform_state_action(self, strategy_step):
        """This state will determine the starting state for kube rootca update

        If the strategy contains the extra_args: 'cert-file' then the vim
        cannot be used until the file is uploaded using sysinv.
        """
        # check extra_args for the strategy
        # if there is a cert_file, we should manually setup the cert
        extra_args = \
            dcmanager_utils.get_sw_update_strategy_extra_args(self.context)
        if extra_args is None:
            extra_args = {}
        cert_file = extra_args.get('cert-file', None)
        if cert_file:
            # this will be validated in the upload state
            self.override_next_state(STRATEGY_STATE_KUBE_ROOTCA_UPDATE_START)
            return self.next_state
        else:
            # no special cert file handling. use a vim strategy (the default)
            return self.next_state
