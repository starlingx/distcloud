# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import utils as cutils
from dcmanager.common import utils


LOG = logging.getLogger(__name__)


class KubernetesAuditData(object):
    def __init__(self, target, version, state):
        self.target = target
        self.version = version
        self.state = state


class KubernetesAudit(object):
    """Manages tasks related to kubernetes audits."""

    def __init__(self):
        LOG.debug("KubernetesAudit initialization...")
        self.audit_count = 0

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kubernetes information

        :return: A list of kubernetes versions on the system controller

        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            endpoint = m_os_ks_client.endpoint_cache.get_endpoint("sysinv")
            sysinv_client = SysinvClient(
                m_os_ks_client.region_name,
                m_os_ks_client.session,
                endpoint=endpoint,
            )
        except Exception:
            LOG.exception("Failed init OS Client, skip kubernetes audit.")
            return None

        regionone_data = []
        regionone_kube_version = None
        results_list = sysinv_client.get_kube_versions()
        for result in results_list:
            regionone_data.append(
                KubernetesAuditData(result.target, result.version, result.state)
            )
            if result.target and result.state == "active":
                regionone_kube_version = result.version
        LOG.debug(f"RegionOne kubernetes versions: {regionone_data}")
        return regionone_kube_version

    @classmethod
    def get_subcloud_audit_data(
        cls, sysinv_client: SysinvClient, subcloud_name: str = None
    ):
        subcloud_kube_upgrades = None
        subcloud_kubernetes_versions = None
        skip_audit = 2 * [dccommon_consts.SKIP_AUDIT]

        try:
            subcloud_kube_upgrades = sysinv_client.get_kube_upgrades()
        except Exception:
            msg = "Failed to get kubernetes upgrades, skip kubernetes audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit

        # If there is a kubernetes upgrade operation in the subcloud,
        # the subcloud can immediately be flagged as out of sync
        if subcloud_kube_upgrades and len(subcloud_kube_upgrades) > 0:
            return subcloud_kube_upgrades, None

        try:
            subcloud_kubernetes_versions = sysinv_client.get_kube_versions()
        except Exception:
            msg = "Failed to get kubernetes versions, skip kubernetes audit."
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
            return skip_audit
        return None, subcloud_kubernetes_versions

    @classmethod
    def get_subcloud_sync_status(
        cls,
        sysinv_client: SysinvClient,
        region_one_version: str,
        subcloud_name: str = None,
    ):

        # Retrieve kubernetes info for this subcloud
        # state - active, partial, available
        # active - true / false
        # version - any value ex: v1.18.1
        subcloud_kube_upgrades, subcloud_kubernetes_versions = (
            cls.get_subcloud_audit_data(sysinv_client, subcloud_name)
        )
        if dccommon_consts.SKIP_AUDIT in [
            subcloud_kube_upgrades,
            subcloud_kubernetes_versions,
        ]:
            return None
        elif subcloud_kube_upgrades and len(subcloud_kube_upgrades) > 0:
            # If there is a kubernetes upgrade operation in the subcloud,
            # the subcloud can immediately be flagged as out of sync
            msg = "Kubernetes upgrade exists"
            cutils.log_subcloud_msg(LOG.debug, msg, subcloud_name)
            return dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        # We will consider it out of sync even for 'partial' state
        for result in subcloud_kubernetes_versions:
            if (
                result.target
                and result.state == "active"
                and result.version == region_one_version
            ):
                return dccommon_consts.SYNC_STATUS_IN_SYNC

        return dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
