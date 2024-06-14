# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
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
from dcmanager.common import utils


LOG = logging.getLogger(__name__)


class KubernetesAuditData(object):
    def __init__(self, target, version, state):
        self.target = target
        self.version = version
        self.state = state

    def to_dict(self):
        return {
            'target': self.target,
            'version': self.version,
            'state': self.state,
        }

    @classmethod
    def from_dict(cls, values):
        if values is None:
            return None
        return cls(**values)


class KubernetesAudit(object):
    """Manages tasks related to kubernetes audits."""

    def __init__(self, context):
        LOG.debug('KubernetesAudit initialization...')
        self.context = context
        self.audit_count = 0

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kubernetes information

        :return: A list of kubernetes versions on the system controller

        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_name=dccommon_consts.DEFAULT_REGION_NAME,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            endpoint = m_os_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(
                dccommon_consts.DEFAULT_REGION_NAME, m_os_ks_client.session,
                endpoint=endpoint)
        except Exception:
            LOG.exception('Failed init OS Client, skip kubernetes audit.')
            return None

        region_one_data = []
        results_list = sysinv_client.get_kube_versions()
        for result in results_list:
            region_one_data.append(KubernetesAuditData(result.target,
                                                       result.version,
                                                       result.state))
        LOG.debug("RegionOne kubernetes versions: %s" % region_one_data)
        return region_one_data

    def subcloud_kubernetes_audit(
        self, sysinv_client, subcloud_name, audit_data
    ):
        LOG.info('Triggered kubernetes audit for: %s' % subcloud_name)

        sync_status = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC

        if not audit_data:
            sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC

            LOG.info(
                f'Kubernetes audit skipped for: {subcloud_name}. There is no audit '
                f'data, requesting sync_status update to {sync_status}'
            )

            return sync_status

        # Retrieve kubernetes info for this subcloud
        # state - active, partial, available
        # active - true / false
        # version - any value ex: v1.18.1

        # Find the target=true state=active version on system controller
        # The audit_data for region one is a dictionary
        region_one_version = None
        for result in audit_data:
            # audit_data will be a dict from passing through RPC, so objectify
            result = KubernetesAuditData.from_dict(result)
            if result.target and result.state == 'active':
                region_one_version = result.version
                break
        if region_one_version is None:
            LOG.info("No active target version found in region one audit data")
            return None

        # if there is a kubernetes upgrade operation in the subcloud,
        # the subcloud can immediately be flagged as out of sync
        subcloud_kube_upgrades = sysinv_client.get_kube_upgrades()
        if len(subcloud_kube_upgrades) > 0:
            # We are out of sync
            LOG.debug('Existing Kubernetes upgrade exists for:(%s)'
                      % subcloud_name)
        else:
            # We will consider it out of sync even for 'partial' state
            # The audit data for subcloud_results is an object not a dictionary
            subcloud_results = sysinv_client.get_kube_versions()
            for result in subcloud_results:
                if result.target and result.state == 'active':
                    subcloud_version = result.version
                    if subcloud_version == region_one_version:
                        sync_status = dccommon_consts.SYNC_STATUS_IN_SYNC
                        break

        LOG.info(
            f'Kubernetes audit completed for: {subcloud_name}, requesting '
            f'sync_status update to {sync_status}'
        )
        return sync_status
