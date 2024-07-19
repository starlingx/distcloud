# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

# TODO(nicodemos): Remove this file after all support to patching is removed
from oslo_log import log as logging
from tsconfig.tsconfig import SW_VERSION

from dccommon import consts
from dcmanager.common import utils

LOG = logging.getLogger(__name__)


# NOTE(nicodemos): Keep the PatchAuditData to avoid breaking the code.
class PatchAuditData(object):
    def __init__(self):
        pass


class PatchAudit(object):
    """Manages tasks related to patch audits."""

    def __init__(self, context):
        LOG.debug("PatchAudit initialization...")
        self.context = context
        self.audit_count = 0

    # NOTE(nicodemos): Keep the get_regionone_audit_data to avoid breaking the code.
    def get_regionone_audit_data(self):
        return PatchAuditData()

    def subcloud_patch_audit(self, keystone_session, subcloud):
        LOG.info("Triggered patch audit for: %s." % subcloud.name)

        # NOTE(nicodemos): Patch audit not supported for 24.09 subcloud
        if subcloud.software_version == SW_VERSION:
            return consts.SYNC_STATUS_NOT_AVAILABLE

        # NOTE(nicodemos): If the subcloud is on the 22.12 release with USM enabled,
        # skip the patch audit.
        if utils.has_usm_service(subcloud.region_name, keystone_session):
            return consts.SYNC_STATUS_NOT_AVAILABLE

        # NOTE(nicodemos): As of version 24.09, the patching orchestration only
        # supports applying specific patches (e.g., USM) using the --patch option.
        # We should return an out-of-sync status to prompt the user to apply the USM
        # patch.
        LOG.info(
            "Need to apply the USM patch to enable the Software audit in "
            f"subcloud: {subcloud.name}."
        )
        return consts.SYNC_STATUS_OUT_OF_SYNC

    # NOTE(nicodemos): Load Audit is not supported anymore;
    def subcloud_load_audit(self):
        return consts.SYNC_STATUS_NOT_AVAILABLE
