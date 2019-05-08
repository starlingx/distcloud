# Copyright 2017-2018 Wind River
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

from keystoneauth1 import exceptions as keystone_exceptions
from neutronclient.common import exceptions as neutronclient_exceptions
from neutronclient.neutron import client as neutronclient

from oslo_log import log as logging
from oslo_serialization import jsonutils

from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.drivers.openstack import sdk
from dcorch.engine import quota_manager
from dcorch.engine.sync_thread import SyncThread
from dcorch.objects import resource

LOG = logging.getLogger(__name__)


class NetworkSyncThread(SyncThread):
    """Manages tasks related to resource management for neutron."""

    def __init__(self, subcloud_engine):
        super(NetworkSyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_NETWORK
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: self.sync_network_resource,
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
                self.sync_network_resource,
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
                self.sync_network_resource,
        }
        # Security group needs to come before security group rule to ensure
        # that the group exists by the time we try to create the rules.
        self.audit_resources = [
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE,
            # note: no audit here for quotas, that's handled separately
        ]
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}
        self.sc_neutron_client = None
        self.initialize()
        LOG.info("NetworkSyncThread initialized", extra=self.log_extra)

    def initialize_sc_clients(self):
        super(NetworkSyncThread, self).initialize_sc_clients()
        if (not self.sc_neutron_client and self.sc_admin_session):
            self.sc_neutron_client = neutronclient.Client(
                "2.0", session=self.sc_admin_session,
                endpoint_type=consts.KS_ENDPOINT_INTERNAL,
                region_name=self.subcloud_engine.subcloud.region_name)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        super(NetworkSyncThread, self).initialize()
        self.m_neutron_client = neutronclient.Client(
            "2.0", session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=consts.VIRTUAL_MASTER_CLOUD)

        self.initialize_sc_clients()
        LOG.info("session and clients initialized", extra=self.log_extra)

    def sync_network_resource(self, request, rsrc):
        self.initialize_sc_clients()
        # Invoke function with name format "operationtype_resourcetype".
        # For example: create_flavor()
        try:
            func_name = request.orch_job.operation_type + \
                "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.error("sync_network_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def put_network_quota_set(self, request, rsrc):
        project_id = request.orch_job.source_resource_id

        # Get the new global limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # Neutron doesn't do user-specific quotas
        user_id = None

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_neutron_client.update_quota(project_id, {"quota": quota_dict})

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quotas {} for tenant {} and user {}"
                 .format(quota_dict, rsrc.master_id, user_id),
                 extra=self.log_extra)

    def delete_network_quota_set(self, request, rsrc):
        # When deleting the quota-set in the master cloud, we don't actually
        # delete it in the subcloud.  Instead we recalculate the subcloud
        # quotas based on the defaults in the master cloud.
        project_id = request.orch_job.source_resource_id
        user_id = None

        # Get the new master quotas
        quota_dict = self.m_neutron_client.show_quota(project_id)['quota']

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_neutron_client.update_quota(project_id, {"quota": quota_dict})

        # Clean up the subcloud resource entry in the DB since it's been
        # deleted in the master cloud.
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if subcloud_rsrc:
            subcloud_rsrc.delete()

    def post_security_group(self, request, rsrc):
        sec_group_dict = jsonutils.loads(request.orch_job.resource_info)
        body = {"security_group": sec_group_dict}

        # Create the security group in the subcloud
        sec_group = self.sc_neutron_client.create_security_group(body)
        sec_group_id = sec_group['security_group']['id']

        # Persist the subcloud resource.
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             sec_group_id)
        LOG.info("Created security group {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, sec_group_dict['name']),
                 extra=self.log_extra)

    def put_security_group(self, request, rsrc):
        sec_group_dict = jsonutils.loads(request.orch_job.resource_info)
        body = {"security_group": sec_group_dict}

        sec_group_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not sec_group_subcloud_rsrc:
            LOG.error("Unable to update security group {}:{},"
                      "cannot find equivalent security group in subcloud."
                      .format(rsrc, sec_group_dict),
                      extra=self.log_extra)
            return

        # Update the security group in the subcloud
        sec_group = self.sc_neutron_client.update_security_group(
            sec_group_subcloud_rsrc.subcloud_resource_id, body)
        sec_group = sec_group['security_group']

        LOG.info("Updated security group: {}:{} [{}]"
                 .format(rsrc.id, sec_group['id'], sec_group['name']),
                 extra=self.log_extra)

    def delete_security_group(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            self.sc_neutron_client.delete_security_group(
                subcloud_rsrc.subcloud_resource_id)
        except neutronclient_exceptions.NotFound:
            # security group already deleted in subcloud, carry on.
            LOG.info("ResourceNotFound in subcloud, may be already deleted",
                     extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Security group {}:{} [{}] deleted"
                 .format(rsrc.id, subcloud_rsrc.id,
                         subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def post_security_group_rule(self, request, rsrc):
        sec_group_rule_dict = jsonutils.loads(request.orch_job.resource_info)

        # Any fields with values of "None" are removed since they are defaults
        # and we can't send them to Neutron.
        for key in sec_group_rule_dict.keys():
            if sec_group_rule_dict[key] is None:
                del sec_group_rule_dict[key]

        try:
            sec_group_rule_dict = self.update_resource_refs(
                consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE,
                sec_group_rule_dict)
        except exceptions.SubcloudResourceNotFound:
            # If we couldn't find the equivalent internal resource refs,
            # we don't know what to create in the subcloud.
            raise exceptions.SyncRequestFailed

        body = {"security_group_rule": sec_group_rule_dict}

        # Create the security group in the subcloud
        try:
            rule = self.sc_neutron_client.create_security_group_rule(body)
            rule_id = rule['security_group_rule']['id']
        except neutronclient.common.exceptions.Conflict:
            # This can happen if we try to create a rule that is already there.
            # If this happens, we'll update our mapping on the next audit.
            LOG.info("Problem creating security group rule {}, neutron says"
                     "it's a duplicate.".format(sec_group_rule_dict))
            # No point in retrying.
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        self.persist_db_subcloud_resource(rsrc.id, rule_id)
        LOG.info("Created security group rule {}:{}"
                 .format(rsrc.id, rule_id),
                 extra=self.log_extra)

    def delete_security_group_rule(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            self.sc_neutron_client.delete_security_group_rule(
                subcloud_rsrc.subcloud_resource_id)
        except neutronclient_exceptions.NotFound:
            # security group rule already deleted in subcloud, carry on.
            LOG.info("ResourceNotFound in subcloud, may be already deleted",
                     extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Security group rule {}:{} [{}] deleted"
                 .format(rsrc.id, subcloud_rsrc.id,
                         subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    # ---- Override common audit functions ----

    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id

        # Else, it is OpenStack resource retrieved from master cloud
        if resource_type in (consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                             consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE):
            return resource['id']

    def get_resource_info(self, resource_type, resource, operation_type=None):
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
            if isinstance(resource, dict):
                tmp = resource.copy()
                del tmp['id']
                return jsonutils.dumps(tmp)
            else:
                return jsonutils.dumps(
                    resource._info.get(
                        consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP))
        elif resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
            if isinstance(resource, dict):
                tmp = resource.copy()
                del tmp['id']
                return jsonutils.dumps(tmp)
            else:
                return jsonutils.dumps(resource._info.get(
                    consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE))
        else:
            return super(NetworkSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def get_resources(self, resource_type, client):
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
            return self.get_security_groups(client)
        elif resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
            return self.get_security_group_rules(client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_subcloud_resources(self, resource_type):
        self.initialize_sc_clients()
        return self.get_resources(resource_type, self.sc_neutron_client)

    def get_master_resources(self, resource_type):
        return self.get_resources(resource_type, self.m_neutron_client)

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
            return self.same_security_group(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
            return self.same_security_group_rule(m_resource, sc_resource)
        else:
            return True

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        if resource_type in [consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                             consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE]:
            # It could be that the group/rule details are different
            # between master cloud and subcloud now.
            # Thus, delete the resource before creating it again.
            self.schedule_work(self.endpoint_type, resource_type,
                               self.get_resource_id(resource_type, m_resource),
                               consts.OPERATION_TYPE_DELETE)
        # Return true to try creating the resource again
        return True

    def map_subcloud_resource(self, resource_type, m_r, m_rsrc_db,
                              sc_resources):
        # Map an existing subcloud resource to an existing master resource.
        # If a mapping is created the function should return True.
        # It is expected that update_resource_refs() has been called on m_r.

        # Used for security groups since there are a couple of default
        # groups (and rules) that get created in the subcloud.
        if resource_type in (consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                             consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE):

            for sc_r in sc_resources:
                if self.same_resource(resource_type, m_r, sc_r):
                    LOG.info(
                        "Mapping resource {} to existing subcloud resource {}"
                        .format(m_r, sc_r), extra=self.log_extra)
                    # If the resource is not even in master cloud resource DB,
                    # create it first.
                    rsrc = m_rsrc_db
                    if not rsrc:
                        master_id = self.get_resource_id(resource_type, m_r)
                        rsrc = resource.Resource(
                            self.ctxt, resource_type=resource_type,
                            master_id=master_id)
                        rsrc.create()
                        LOG.info("Resource created in DB {}/{}/{}".format(
                            rsrc.id, resource_type, master_id))

                    self.persist_db_subcloud_resource(rsrc.id,
                                                      sc_r['id'])
                    return True
        return False

    def update_resource_refs(self, resource_type, m_r):
        # Update any references in m_r to other resources in the master cloud
        # to use the equivalent subcloud resource instead.
        m_r = m_r.copy()
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:

            if m_r.get('security_group_id') is not None:
                # If the security group id is in the dict then it is for the
                # master region, and we need to update it with the equivalent
                # id from the subcloud.
                master_sec_group_id = m_r['security_group_id']
                sec_group_rsrc = resource.Resource.get_by_type_and_master_id(
                    self.ctxt, consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                    master_sec_group_id)
                sec_group_subcloud_rsrc = self.get_db_subcloud_resource(
                    sec_group_rsrc.id)
                if sec_group_subcloud_rsrc:
                    m_r['security_group_id'] = \
                        sec_group_subcloud_rsrc.subcloud_resource_id
                else:
                    LOG.error(
                        "Unable to update security group id in {},"
                        "cannot find equivalent security group in subcloud."
                        .format(m_r), extra=self.log_extra)
                    raise exceptions.SubcloudResourceNotFound(
                        resource=sec_group_rsrc.id)

            if m_r.get('remote_group_id') is not None:
                # If the remote group id is in the dict then it is for the
                # master region, and we need to update it with the equivalent
                # id from the subcloud.
                master_remote_group_id = m_r['remote_group_id']
                remote_group_rsrc = \
                    resource.Resource.get_by_type_and_master_id(
                        self.ctxt, consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                        master_remote_group_id)
                remote_group_subcloud_rsrc = self.get_db_subcloud_resource(
                    remote_group_rsrc.id)
                if remote_group_subcloud_rsrc:
                    m_r['remote_group_id'] = \
                        remote_group_subcloud_rsrc.subcloud_resource_id
                else:
                    LOG.error(
                        "Unable to update remote group id in {},"
                        "cannot find equivalent remote group in subcloud."
                        .format(m_r), extra=self.log_extra)
                    raise exceptions.SubcloudResourceNotFound(
                        resource=sec_group_rsrc.id)
        return m_r

    # This will only be called by the audit code.
    def create_security_group(self, request, rsrc):
        self.post_security_group(request, rsrc)

    # This will only be called by the audit code.
    def create_security_group_rule(self, request, rsrc):
        self.post_security_group_rule(request, rsrc)

    def same_security_group(self, qc1, qc2):
        # Fetch the tenant name from the project. Tenant ids are different
        # between regions.
        # TODO(kbujold): This solution only works if we have one domain within
        # keystone.
        qc1_tenant_name = sdk.OpenStackDriver().get_project_by_id(
            qc1['tenant_id']).name
        qc2_tenant_name = sdk.OpenStackDriver(
            self.subcloud_engine.subcloud.region_name).get_project_by_id(
            qc2['tenant_id']).name

        return (qc1['description'] == qc2['description'] and
                qc1_tenant_name == qc2_tenant_name and
                qc1['name'] == qc2['name'])

    def same_security_group_rule(self, qc1, qc2):
        # Ignore id, created_at, updated_at, and revision_number

        # Fetch the tenant name from the project. Tenant id are different
        # between regions.
        qc1_tenant_name = sdk.OpenStackDriver().get_project_by_id(
            qc1['tenant_id']).name
        qc2_tenant_name = sdk.OpenStackDriver(
            self.subcloud_engine.subcloud.region_name).get_project_by_id(
            qc2['tenant_id']).name

        return (qc1['description'] == qc2['description'] and
                qc1_tenant_name == qc2_tenant_name and
                qc1['project_id'] == qc2['project_id'] and
                qc1['direction'] == qc2['direction'] and
                qc1['protocol'] == qc2['protocol'] and
                qc1['ethertype'] == qc2['ethertype'] and
                qc1['remote_group_id'] == qc2['remote_group_id'] and
                qc1['security_group_id'] == qc2['security_group_id'] and
                qc1['remote_ip_prefix'] == qc2['remote_ip_prefix'] and
                qc1['port_range_min'] == qc2['port_range_min'] and
                qc1['port_range_max'] == qc2['port_range_max'])

    def get_security_groups(self, nc):
        try:
            # Only retrieve the info we care about.
            # created_at, updated_at, and revision_number can't be specified
            # when making a new group.  tags would require special handling,
            # and security_group_rules is handled separately.
            groups = nc.list_security_groups(
                retrieve_all=True,
                fields=['id', 'name', 'description', 'tenant_id'])
            groups = groups['security_groups']
            return groups
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_flavor: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_security_group_rules(self, nc):
        try:
            rules = nc.list_security_group_rules(retrieve_all=True)
            rules = rules['security_group_rules']
            for rule in rules:
                # We don't need these for comparing/creating security groups
                # and/or they're not allowed in POST calls.
                del rule['created_at']
                del rule['updated_at']
                del rule['revision_number']
                # These would have to be handled separately, not yet supported.
                rule.pop('tags', None)
                # Some rules have a blank description as an empty string, some
                # as None, depending on whether they were auto-created during
                # security group creation or added later.  Convert the empty
                # strings to None.
                if rule['description'] == '':
                    rule['description'] = None
            return rules
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_flavor: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None
