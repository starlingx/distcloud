# Copyright (c) 2021, 2024-2025 Wind River Systems, Inc.
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

from dccommon import consts as dccommon_consts
from dcmanager.db import api as db_api


LOG = logging.getLogger(__name__)


def request_subcloud_audits(
    context,
    update_subcloud_state=False,
    audit_firmware=False,
    audit_kubernetes=False,
    audit_kube_rootca=False,
    audit_software=False,
):
    values = {}
    if update_subcloud_state:
        values["state_update_requested"] = True
    if audit_firmware:
        values["firmware_audit_requested"] = True
    if audit_kubernetes:
        values["kubernetes_audit_requested"] = True
    if audit_kube_rootca:
        values["kube_rootca_update_audit_requested"] = True
    if audit_software:
        values["software_audit_requested"] = True
    if values:
        db_api.subcloud_audits_update_all(context, values)


def filter_endpoint_data(context, subcloud, endpoint_data):
    if endpoint_data:
        LOG.debug(
            f"Endpoint status before filtering for {subcloud.name}: {endpoint_data}"
        )
        subcloud_statuses = db_api.subcloud_status_get_all(context, subcloud.id)
        for subcloud_status in subcloud_statuses:
            endpoint_type = subcloud_status.endpoint_type
            # If an audit needs to be skipped, DCAgent will return a SKIP_AUDIT status,
            # which is converted to None in the endpoint_data and needs to be
            # removed to avoid sending it to state.
            if endpoint_type in endpoint_data and (
                endpoint_data[endpoint_type] == subcloud_status.sync_status
                or endpoint_data[endpoint_type] is None
            ):
                del endpoint_data[endpoint_type]
        LOG.debug(
            f"Endpoint status after filtering for {subcloud.name}: {endpoint_data}"
        )


def update_subcloud_software_version(context, subcloud, endpoint_data, dcorch_client):
    if not endpoint_data:
        return

    data = endpoint_data.get(dccommon_consts.AUDIT_TYPE_SOFTWARE)
    if not data or not isinstance(data, dict):
        return

    sync_status = data.get("sync_status")
    software_version = data.get("software_version")

    if software_version and software_version != subcloud.software_version:
        LOG.debug(
            f"Updating subcloud {subcloud.name} software verion in dcorch and "
            f"dcmanager databases to {software_version}."
        )
        # Update in dcorch database
        dcorch_client.update_subcloud_version(
            context, subcloud.region_name, software_version
        )
        # Update in dcmanager database
        db_api.subcloud_update(
            context,
            subcloud.id,
            software_version=software_version,
        )

    # Update the software corresponding endpoint_data by returnning only
    # sync_status for subsequent processing.
    endpoint_data[dccommon_consts.AUDIT_TYPE_SOFTWARE] = sync_status
