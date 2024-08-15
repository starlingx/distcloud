# Copyright (c) 2021, 2024 Wind River Systems, Inc.
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
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.

from oslo_log import log as logging

from dcmanager.db import api as db_api


LOG = logging.getLogger(__name__)


def request_subcloud_audits(
    context,
    update_subcloud_state=False,
    audit_patch=False,
    audit_load=False,
    audit_firmware=False,
    audit_kubernetes=False,
    audit_kube_rootca=False,
    audit_software=False,
):
    values = {}
    if update_subcloud_state:
        values["state_update_requested"] = True
    if audit_patch:
        values["patch_audit_requested"] = True
    if audit_load:
        values["load_audit_requested"] = True
    if audit_firmware:
        values["firmware_audit_requested"] = True
    if audit_kubernetes:
        values["kubernetes_audit_requested"] = True
    if audit_kube_rootca:
        values["kube_rootca_update_audit_requested"] = True
    if audit_software:
        values["spare_audit_requested"] = True
    db_api.subcloud_audits_update_all(context, values)


def filter_endpoint_data(context, subcloud, endpoint_data):
    if endpoint_data:
        LOG.debug(
            f"Endpoint status before filtering for {subcloud.name}: {endpoint_data}"
        )
        subcloud_statuses = db_api.subcloud_status_get_all(context, subcloud.id)
        for subcloud_status in subcloud_statuses:
            endpoint_type = subcloud_status.endpoint_type
            if (
                endpoint_type in endpoint_data
                and endpoint_data[endpoint_type] == subcloud_status.sync_status
            ):
                del endpoint_data[endpoint_type]
        LOG.debug(
            f"Endpoint status after filtering for {subcloud.name}: {endpoint_data}"
        )
