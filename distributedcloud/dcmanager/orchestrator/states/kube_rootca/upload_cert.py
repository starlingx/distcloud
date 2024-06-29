#
# Copyright (c) 2021, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common.consts import (
    STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
)
from dcmanager.common.exceptions import CertificateUploadError
from dcmanager.common import utils as dcmanager_utils
from dcmanager.orchestrator.states.base import BaseState


class KubeRootcaUpdateUploadCertState(BaseState):
    """Upload a kube rootca certificate from the vault"""

    def __init__(self, region_name):
        super(KubeRootcaUpdateUploadCertState, self).__init__(
            next_state=STRATEGY_STATE_CREATING_VIM_KUBE_ROOTCA_UPDATE_STRATEGY,
            region_name=region_name,
        )

    def perform_state_action(self, strategy_step):
        """Upload the cert. Only a valid state if the update is started"""

        # Get the cert-file from the extra_args of the strategy
        extra_args = dcmanager_utils.get_sw_update_strategy_extra_args(self.context)
        if extra_args is None:
            extra_args = {}
        cert_file = extra_args.get("cert-file", None)
        if cert_file:
            with open(cert_file, "rb") as pem_file:
                cert_upload = self.get_sysinv_client(
                    self.region_name
                ).kube_rootca_update_upload_cert(pem_file)
            # If the upload has an error, we fail the state
            # this will log the error and subcloud info
            if cert_upload.get("error"):
                raise CertificateUploadError(err=cert_upload.get("error"))

        else:
            # developer error.  We should not have attempted the cert upload
            # transition to the VIM state
            self.warn_log(strategy_step, "No cert-file found in extra_args")

        # Move to the next stage
        return self.next_state
