#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import patching_v1
from dcmanager.common import utils
from dcmanager.orchestrator.orch_thread import OrchThread

LOG = logging.getLogger(__name__)


class PatchJobData(object):
    """Job data initialized once and shared across state operators"""

    def __init__(self, context):
        self.context = context
        self.initialize_data()

    def initialize_data(self):
        LOG.info("Initializing PatchOrchThread job data")

        loads = OrchThread.get_sysinv_client(
            dccommon_consts.DEFAULT_REGION_NAME).get_loads()

        installed_loads = utils.get_loads_for_patching(loads)

        self.region_one_patches = OrchThread.get_patching_client(
            dccommon_consts.DEFAULT_REGION_NAME).query()

        self.region_one_applied_patch_ids = []
        self.region_one_commited_patch_ids = []
        for patch_id, patch in self.region_one_patches.items():
            # Only the patches for the installed loads will be stored
            if patch["sw_version"] in installed_loads:
                if patch["repostate"] == patching_v1.PATCH_STATE_APPLIED:
                    self.region_one_applied_patch_ids.append(patch_id)
                elif patch["repostate"] == patching_v1.PATCH_STATE_COMMITTED:
                    self.region_one_commited_patch_ids.append(patch_id)
                    # A commited patch is also an applied one
                    self.region_one_applied_patch_ids.append(patch_id)

        self.extra_args = utils.get_sw_update_strategy_extra_args(self.context)
