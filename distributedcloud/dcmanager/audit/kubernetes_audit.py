# Copyright 2017 Ericsson AB.
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
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

from dcorch.common import consts as dcorch_consts

from dcmanager.common import consts


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

    def __init__(self, context, dcmanager_rpc_client):
        LOG.debug('KubernetesAudit initialization...')
        self.context = context
        self.dcmanager_rpc_client = dcmanager_rpc_client
        self.audit_count = 0

    def _update_subcloud_sync_status(self, sc_name, sc_endpoint_type,
                                     sc_status):
        self.dcmanager_rpc_client.update_subcloud_endpoint_status(
            self.context,
            subcloud_name=sc_name,
            endpoint_type=sc_endpoint_type,
            sync_status=sc_status)

    def get_regionone_audit_data(self):
        """Query RegionOne to determine kubernetes information

        :return: A list of kubernetes versions on the system controller

        """
        try:
            m_os_ks_client = OpenStackDriver(
                region_name=consts.DEFAULT_REGION_NAME,
                region_clients=None).keystone_client
            endpoint = m_os_ks_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(
                consts.DEFAULT_REGION_NAME, m_os_ks_client.session,
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

    def subcloud_kubernetes_audit(self, subcloud_name, audit_data):
        LOG.info('Triggered kubernetes audit for: %s' % subcloud_name)
        if not audit_data:
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_KUBERNETES,
                consts.SYNC_STATUS_IN_SYNC)
            LOG.debug('No region one audit data, exiting kubernetes audit')
            return
        try:
            sc_os_client = OpenStackDriver(region_name=subcloud_name,
                                           region_clients=None).keystone_client
            endpoint = sc_os_client.endpoint_cache.get_endpoint('sysinv')
            sysinv_client = SysinvClient(subcloud_name, sc_os_client.session,
                                         endpoint=endpoint)
        except (keystone_exceptions.EndpointNotFound,
                keystone_exceptions.ConnectFailure,
                keystone_exceptions.ConnectTimeout,
                IndexError):
            LOG.exception("Endpoint for online subcloud:(%s) not found, skip "
                          "kubernetes audit." % subcloud_name)
            return

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
            return

        out_of_sync = True

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
                        out_of_sync = False
                        break

        if out_of_sync:
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_KUBERNETES,
                consts.SYNC_STATUS_OUT_OF_SYNC)
        else:
            self._update_subcloud_sync_status(
                subcloud_name, dcorch_consts.ENDPOINT_TYPE_KUBERNETES,
                consts.SYNC_STATUS_IN_SYNC)
        LOG.info('Kubernetes audit completed for: %s' % subcloud_name)
