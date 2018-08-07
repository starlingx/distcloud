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

from cinderclient import client as cinderclient
from keystoneauth1 import exceptions as keystone_exceptions

from oslo_log import log as logging
from oslo_serialization import jsonutils

from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.engine import quota_manager
from dcorch.engine.sync_thread import SyncThread

LOG = logging.getLogger(__name__)


class VolumeSyncThread(SyncThread):
    """Manages tasks related to resource management for cinder."""

    def __init__(self, subcloud_engine):
        super(VolumeSyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_VOLUME
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_VOLUME_QUOTA_SET: self.sync_volume_resource,
            consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
                self.sync_volume_resource,
        }
        self.audit_resources = [
            consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET,
            # note: no audit here for quotas, that's handled separately
        ]
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name,
            self.endpoint_type)}
        # define the subcloud clients
        self.sc_cinder_client = None
        self.initialize()
        LOG.info("VolumeSyncThread initialized", extra=self.log_extra)

    def initialize_sc_clients(self):
        super(VolumeSyncThread, self).initialize_sc_clients()
        if (not self.sc_cinder_client and self.sc_admin_session):
            self.sc_cinder_client = cinderclient.Client(
                "3.0", session=self.sc_admin_session,
                endpoint_type=consts.KS_ENDPOINT_INTERNAL,
                region_name=self.subcloud_engine.subcloud.region_name)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        super(VolumeSyncThread, self).initialize()
        self.m_cinder_client = cinderclient.Client(
            "3.0", session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=consts.VIRTUAL_MASTER_CLOUD)

        self.initialize_sc_clients()
        LOG.info("session and clients initialized", extra=self.log_extra)

    def sync_volume_resource(self, request, rsrc):
        self.initialize_sc_clients()
        # Invoke function with name format "operationtype_resourcetype".
        # For example: create_flavor()
        try:
            func_name = request.orch_job.operation_type + \
                "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except keystone_exceptions.EndpointNotFound as e:
            # Cinder is optional in the subcloud, so this isn't considered
            # an error.
            LOG.info("sync_volume_resource: {} does not have a volume "
                     "endpoint in keystone"
                     .format(self.subcloud_engine.subcloud.region_name),
                     extra=self.log_extra)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.error("sync_volume_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def put_volume_quota_set(self, request, rsrc):
        project_id = request.orch_job.source_resource_id

        # Get the new global limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # Cinder doesn't do user-specific quotas
        user_id = None

        # The client code may set a tenant_id field.  If so, remove it
        # since it's not defined in the API.
        quota_dict.pop('tenant_id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_cinder_client.quotas.update(project_id, **quota_dict)

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quotas {} for tenant {} and user {}"
                 .format(quota_dict, rsrc.master_id, user_id),
                 extra=self.log_extra)

    def delete_volume_quota_set(self, request, rsrc):
        # When deleting the quota-set in the master cloud, we don't actually
        # delete it in the subcloud.  Instead we recalculate the subcloud
        # quotas based on the defaults in the master cloud.

        project_id = request.orch_job.source_resource_id
        user_id = None

        # Get the new master quotas
        quota_dict = self.m_cinder_client.quotas.get(project_id).to_dict()

        # Remove the 'id' key before doing calculations.
        quota_dict.pop('id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_cinder_client.quotas.update(project_id, **quota_dict)

        # Clean up the subcloud resource entry in the DB since it's been
        # deleted in the master cloud.
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if subcloud_rsrc:
            subcloud_rsrc.delete()

    def put_quota_class_set(self, request, rsrc):
        # Only a class_id of "default" is meaningful to cinder.
        class_id = request.orch_job.source_resource_id

        # Get the new quota class limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # If this is coming from the audit we need to remove the "id" field.
        quota_dict.pop('id', None)

        # The client code may set a class name.  If so, remove it since it's
        # not defined in the API.
        quota_dict.pop('class_name', None)

        # Apply the new quota class limits to the subcloud.
        self.sc_cinder_client.quota_classes.update(class_id, **quota_dict)

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quota classes {} for class {}"
                 .format(quota_dict, rsrc.master_id),
                 extra=self.log_extra)

    # ---- Override common audit functions ----
    def get_resource_id(self, resource_type, resource):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            # We only care about the default class.
            return 'default'
        else:
            return super(VolumeSyncThread, self).get_resource_id(
                resource_type, resource)

    def get_resource_info(self, resource_type, resource, operation_type=None):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return jsonutils.dumps(resource._info)
        else:
            return super(VolumeSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def get_subcloud_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            # No-op if clients were initialized previously
            self.initialize_sc_clients()
            return self.get_quota_class_resources(self.sc_cinder_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_master_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.m_cinder_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return self.same_quota_class(m_resource, sc_resource)
        else:
            return True

    # This will only be called by the audit code.
    def create_quota_class_set(self, request, rsrc):
        self.put_quota_class_set(request, rsrc)

    def same_quota_class(self, qc1, qc2):
        # The audit code will pass in QuotaClassSet objects, we need to
        # convert them before comparing them.
        return qc1.to_dict() == qc2.to_dict()

    def get_quota_class_resources(self, nc):
        # We only care about the "default" class since it's the only one
        # that actually affects cinder.
        try:
            quota_class = nc.quota_classes.get('default')
            return [quota_class]
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_quota_class: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except keystone_exceptions.EndpointNotFound as e:
            LOG.info("get_quota_class: subcloud {} does not have a volume "
                     "endpoint in keystone"
                     .format(self.subcloud_engine.subcloud.region_name),
                     extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None
