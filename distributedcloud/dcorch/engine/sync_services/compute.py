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
from novaclient import client as novaclient
from novaclient import exceptions as novaclient_exceptions
from novaclient import utils as novaclient_utils

from oslo_log import log as logging
from oslo_serialization import jsonutils

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.common import utils
from dcorch.engine import quota_manager
from dcorch.engine.sync_thread import SyncThread

LOG = logging.getLogger(__name__)


class ComputeSyncThread(SyncThread):
    """Manages tasks related to resource management for nova."""

    def __init__(self, subcloud_engine):
        super(ComputeSyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_COMPUTE
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR: self.sync_compute_resource,
            consts.RESOURCE_TYPE_COMPUTE_KEYPAIR: self.sync_compute_resource,
            consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET: self.sync_compute_resource,
            consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
                self.sync_compute_resource,
        }
        self.audit_resources = [
            consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET,
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
            consts.RESOURCE_TYPE_COMPUTE_KEYPAIR,
            # note: no audit here for quotas, that's handled separately
        ]
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}
        self.sc_nova_client = None
        self.initialize()
        LOG.info("ComputeSyncThread initialized", extra=self.log_extra)

    def initialize_sc_clients(self):
        super(ComputeSyncThread, self).initialize_sc_clients()
        if (not self.sc_nova_client and self.sc_admin_session):
            self.sc_nova_client = novaclient.Client(
                '2.38', session=self.sc_admin_session,
                endpoint_type=dccommon_consts.KS_ENDPOINT_ADMIN,
                region_name=self.subcloud_engine.subcloud.region_name)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        super(ComputeSyncThread, self).initialize()
        # todo: update version to 2.53 once on pike
        self.m_nova_client = novaclient.Client(
            '2.38', session=self.admin_session,
            endpoint_type=dccommon_consts.KS_ENDPOINT_INTERNAL,
            region_name=dccommon_consts.VIRTUAL_MASTER_CLOUD)

        self.initialize_sc_clients()
        LOG.info("session and clients initialized", extra=self.log_extra)

    def sync_compute_resource(self, request, rsrc):
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
            LOG.error("sync_compute_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    # ---- Override common audit functions ----
    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id

        # Else, it is OpenStack resource retrieved from master cloud
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            # User_id field is set in _info data by audit query code.
            return utils.keypair_construct_id(
                resource.id, resource._info['keypair']['user_id'])
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            # We only care about the default class.
            return 'default'

        # Nothing special for other resources (flavor)
        return resource.id

    def get_resource_info(self, resource_type, resource, operation_type=None):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return jsonutils.dumps(resource._info)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            return jsonutils.dumps(resource._info.get('keypair'))
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return jsonutils.dumps(resource._info)
        else:
            return super(ComputeSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def get_subcloud_resources(self, resource_type):
        self.initialize_sc_clients()
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return self.get_flavor_resources(self.sc_nova_client)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.sc_nova_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_master_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return self.get_flavor_resources(self.m_nova_client)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.m_nova_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return self.same_flavor(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            return self.same_keypair(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return self.same_quota_class(m_resource, sc_resource)
        else:
            return True

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        if resource_type in [consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
                             consts.RESOURCE_TYPE_COMPUTE_KEYPAIR]:
            # It could be that the flavor details are different
            # between master cloud and subcloud now.
            # Thus, delete the flavor before creating it again.
            # Dependants (ex: flavor-access) will be created again.
            self.schedule_work(self.endpoint_type, resource_type,
                               self.get_resource_id(resource_type, m_resource),
                               consts.OPERATION_TYPE_DELETE)

        # For quota classes there is no delete operation, so we just want
        # to update the existing class.  Nothing to do here.

        # Return true to try creating the resource again
        return True

    # ---- Flavor & dependants (flavor-access, extra-spec) ----
    def create_flavor(self, request, rsrc):
        flavor_dict = jsonutils.loads(request.orch_job.resource_info)
        name = flavor_dict['name']
        ram = flavor_dict['ram']
        vcpus = flavor_dict['vcpus']
        disk = flavor_dict['disk']
        kwargs = {}
        # id is always passed in by proxy
        kwargs['flavorid'] = flavor_dict['id']
        if 'OS-FLV-EXT-DATA:ephemeral' in flavor_dict:
            kwargs['ephemeral'] = flavor_dict['OS-FLV-EXT-DATA:ephemeral']
        if 'swap' in flavor_dict and flavor_dict['swap']:
            kwargs['swap'] = flavor_dict['swap']
        if 'rxtx_factor' in flavor_dict:
            kwargs['rxtx_factor'] = flavor_dict['rxtx_factor']
        if 'os-flavor-access:is_public' in flavor_dict:
            kwargs['is_public'] = flavor_dict['os-flavor-access:is_public']

        # todo: maybe we can bypass all the above and just directly call
        # self.sc_nova_client.flavors._create("/flavors", body, "flavor")
        # with "body" made from request.orch_job.resource_info.
        newflavor = None
        try:
            newflavor = self.sc_nova_client.flavors.create(
                name, ram, vcpus, disk, **kwargs)
        except novaclient_exceptions.Conflict as e:
            if "already exists" in e.message:
                # FlavorExists or FlavorIdExists.
                LOG.info("Flavor {} already exists in subcloud"
                         .format(name), extra=self.log_extra)
                # Compare the flavor details and recreate flavor if required.
                newflavor = self.recreate_flavor_if_reqd(name, ram, vcpus,
                                                         disk, kwargs)
            else:
                LOG.exception(e)
        if not newflavor:
            raise exceptions.SyncRequestFailed

        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, newflavor.id)
        LOG.info("Flavor {}:{} [{}/{}] created"
                 .format(rsrc.id, subcloud_rsrc_id, name, newflavor.id),
                 extra=self.log_extra)

    def recreate_flavor_if_reqd(self, name, ram, vcpus, disk, kwargs):
        # Both the flavor name and the flavor id must be unique.
        # If the conflict is due to same name, but different uuid,
        # we have to fetch the correct id from subcloud before
        # attempting to delete it.
        # Since the flavor details are available, compare with master cloud
        # and recreate the flavor only if required.
        newflavor = None
        try:
            master_flavor = self.m_nova_client.flavors.get(kwargs['flavorid'])
            subcloud_flavor = None
            sc_flavors = self.sc_nova_client.flavors.list(is_public=None)
            for sc_flavor in sc_flavors:
                # subcloud flavor might have the same name and/or the same id
                if name == sc_flavor.name or \
                        kwargs['flavorid'] == sc_flavor.id:
                    subcloud_flavor = sc_flavor
                    break
            if master_flavor and subcloud_flavor:
                if self.same_flavor(master_flavor, subcloud_flavor):
                    newflavor = subcloud_flavor
                else:
                    LOG.info("recreate_flavor, deleting {}:{}".format(
                             subcloud_flavor.name, subcloud_flavor.id),
                             extra=self.log_extra)
                    self.sc_nova_client.flavors.delete(subcloud_flavor.id)
                    newflavor = self.sc_nova_client.flavors.create(
                        name, ram, vcpus, disk, **kwargs)
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailed
        return newflavor

    def delete_flavor(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            self.sc_nova_client.flavors.delete(
                subcloud_rsrc.subcloud_resource_id)
        except novaclient_exceptions.NotFound:
            # Flavor already deleted in subcloud, carry on.
            LOG.info("ResourceNotFound in subcloud, may be already deleted",
                     extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Flavor {}:{} [{}] deleted".format(rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def action_flavor(self, request, rsrc):
        action_dict = jsonutils.loads(request.orch_job.resource_info)
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            LOG.error("Subcloud resource missing for {}:{}"
                      .format(rsrc, action_dict),
                      extra=self.log_extra)
            return

        switcher = {
            consts.ACTION_ADDTENANTACCESS: self.add_tenant_access,
            consts.ACTION_REMOVETENANTACCESS: self.remove_tenant_access,
            consts.ACTION_EXTRASPECS_POST: self.set_extra_specs,
            consts.ACTION_EXTRASPECS_DELETE: self.unset_extra_specs,
        }
        action = list(action_dict.keys())[0]
        if action not in switcher.keys():
            LOG.error("Unsupported flavor action {}".format(action),
                      extra=self.log_extra)
            return
        LOG.info("Flavor action [{}]: {}".format(action, action_dict),
                 extra=self.log_extra)
        switcher[action](rsrc, action, action_dict, subcloud_rsrc)

    def add_tenant_access(self, rsrc, action, action_dict, subcloud_rsrc):
            tenant_id = action_dict[action]['tenant']
            try:
                self.sc_nova_client.flavor_access.add_tenant_access(
                    subcloud_rsrc.subcloud_resource_id, tenant_id)
            except novaclient_exceptions.Conflict:
                LOG.info("Flavor-access already present {}:{}"
                         .format(rsrc, action_dict),
                         extra=self.log_extra)

    def remove_tenant_access(self, rsrc, action, action_dict, subcloud_rsrc):
            tenant_id = action_dict[action]['tenant']
            try:
                self.sc_nova_client.flavor_access.remove_tenant_access(
                    subcloud_rsrc.subcloud_resource_id, tenant_id)
            except novaclient_exceptions.NotFound:
                LOG.info("Flavor-access already deleted {}:{}"
                         .format(rsrc, action_dict),
                         extra=self.log_extra)

    def set_extra_specs(self, rsrc, action, action_dict, subcloud_rsrc):
            flavor = novaclient_utils.find_resource(
                self.sc_nova_client.flavors,
                subcloud_rsrc.subcloud_resource_id, is_public=None)
            flavor.set_keys(action_dict[action])
            # No need to handle "extra-spec already exists" case.
            # Nova throws no exception for that.

    def unset_extra_specs(self, rsrc, action, action_dict, subcloud_rsrc):
            flavor = novaclient_utils.find_resource(
                self.sc_nova_client.flavors,
                subcloud_rsrc.subcloud_resource_id, is_public=None)

            es_metadata = action_dict[action]
            metadata = {}
            # extra_spec keys passed in could be of format "key1"
            # or "key1;key2;key3"
            for metadatum in es_metadata.split(';'):
                if metadatum:
                    metadata[metadatum] = None

            try:
                flavor.unset_keys(list(metadata.keys()))
            except novaclient_exceptions.NotFound:
                LOG.info("Extra-spec {} not found {}:{}"
                         .format(list(metadata.keys()), rsrc, action_dict),
                         extra=self.log_extra)

    def get_flavor_resources(self, nc):
        try:
            flavors = nc.flavors.list(is_public=None)
            for flavor in flavors:
                # Attach flavor access list to flavor object, so that
                # it can be audited later in audit_dependants()
                if not flavor.is_public:
                    try:
                        fa_list = nc.flavor_access.list(flavor=flavor.id)
                        flavor.attach_fa = fa_list
                    except novaclient_exceptions.NotFound:
                        # flavor/flavor_access just got deleted
                        # (after flavors.list)
                        LOG.info("Flavor/flavor_access not found [{}]"
                                 .format(flavor.id),
                                 extra=self.log_extra)
                        flavor.attach_fa = []
                else:
                    flavor.attach_fa = []

                # Attach extra_spec dict to flavor object, so that
                # it can be audited later in audit_dependants()
                flavor.attach_es = flavor.get_keys()
            return flavors
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_flavor: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def same_flavor(self, f1, f2):
        return (f1.name == f2.name and
                f1.vcpus == f2.vcpus and
                f1.ram == f2.ram and
                f1.disk == f2.disk and
                f1.swap == f2.swap and
                f1.rxtx_factor == f2.rxtx_factor and
                f1.is_public == f2.is_public and
                f1.ephemeral == f2.ephemeral)

    def audit_dependants(self, resource_type, m_flavor, sc_flavor):
        num_of_audit_jobs = 0
        if not self.subcloud_engine.is_enabled() or self.should_exit():
            return num_of_audit_jobs
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            num_of_audit_jobs += self.audit_flavor_access(
                resource_type, m_flavor, sc_flavor)
            num_of_audit_jobs += self.audit_extra_specs(
                resource_type, m_flavor, sc_flavor)
        return num_of_audit_jobs

    def audit_flavor_access(self, resource_type, m_flavor, sc_flavor):
        num_of_audit_jobs = 0
        sc_fa_attachment = []  # Subcloud flavor-access attachment
        if sc_flavor:
            sc_fa_attachment = sc_flavor.attach_fa

        # Flavor-access needs to be audited. flavor-access details are
        # filled in m_resources and sc_resources during query.
        for m_fa in m_flavor.attach_fa:
            found = False
            for sc_fa in sc_fa_attachment:
                if m_fa.tenant_id == sc_fa.tenant_id:
                    found = True
                    sc_flavor.attach_fa.remove(sc_fa)
                    break
            if not found:
                action_dict = {
                    consts.ACTION_ADDTENANTACCESS: {"tenant": m_fa.tenant_id}}
                self.schedule_work(
                    self.endpoint_type, resource_type, m_flavor.id,
                    consts.OPERATION_TYPE_ACTION,
                    jsonutils.dumps(action_dict))
                num_of_audit_jobs += 1

        for sc_fa in sc_fa_attachment:
            action_dict = {
                consts.ACTION_REMOVETENANTACCESS: {"tenant": sc_fa.tenant_id}}
            self.schedule_work(
                self.endpoint_type, resource_type, m_flavor.id,
                consts.OPERATION_TYPE_ACTION,
                jsonutils.dumps(action_dict))
            num_of_audit_jobs += 1

        return num_of_audit_jobs

    def audit_extra_specs(self, resource_type, m_flavor, sc_flavor):
        num_of_audit_jobs = 0
        sc_es_attachment = {}  # Subcloud extra-spec attachment
        if sc_flavor:
            # sc_flavor could be None.
            sc_es_attachment = sc_flavor.attach_es

        # Extra-spec needs to be audited. Extra-spec details are
        # filled in m_resources and sc_resources during query.
        metadata = {}
        for m_key, m_value in m_flavor.attach_es.items():
            found = False
            for sc_key, sc_value in sc_es_attachment.items():
                if m_key == sc_key and m_value == sc_value:
                    found = True
                    sc_es_attachment.pop(sc_key)
                    break
            if not found:
                metadata.update({m_key: m_value})
        if metadata:
            action_dict = {consts.ACTION_EXTRASPECS_POST: metadata}
            self.schedule_work(
                self.endpoint_type, resource_type, m_flavor.id,
                consts.OPERATION_TYPE_ACTION, jsonutils.dumps(action_dict))
            num_of_audit_jobs += 1

        keys_to_delete = ""
        for sc_key, sc_value in sc_es_attachment.items():
            keys_to_delete += sc_key + ";"
        if keys_to_delete:
            action_dict = {consts.ACTION_EXTRASPECS_DELETE: keys_to_delete}
            self.schedule_work(
                self.endpoint_type, resource_type, m_flavor.id,
                consts.OPERATION_TYPE_ACTION, jsonutils.dumps(action_dict))
            num_of_audit_jobs += 1

        return num_of_audit_jobs

    # ---- Keypair resource ----
    def create_keypair(self, request, rsrc):
        keypair_dict = jsonutils.loads(request.orch_job.resource_info)
        name, user_id = utils.keypair_deconstruct_id(rsrc.master_id)
        log_str = rsrc.master_id + ' ' + name + '/' + user_id
        kwargs = {}
        kwargs['user_id'] = user_id
        if 'public_key' in keypair_dict:
            kwargs['public_key'] = keypair_dict['public_key']
        if 'type' in keypair_dict:
            kwargs['key_type'] = keypair_dict['type']
            log_str += "/" + kwargs['key_type']
        newkeypair = None
        try:
            newkeypair = self.sc_nova_client.keypairs.create(name, **kwargs)
        except novaclient_exceptions.Conflict:
            # KeyPairExists: keypair with same name already exists.
            LOG.info("Keypair {} already exists in subcloud"
                     .format(log_str), extra=self.log_extra)
            newkeypair = self.recreate_keypair(name, kwargs)
        if not newkeypair:
            raise exceptions.SyncRequestFailed

        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, rsrc.master_id)
        LOG.info("Keypair {}:{} [{}] created".format(rsrc.id,
                 subcloud_rsrc_id, log_str),
                 extra=self.log_extra)

    def recreate_keypair(self, name, kwargs):
        newkeypair = None
        try:
            # Not worth doing additional api calls to compare the
            # master and subcloud keypairs. Delete and create again.
            # This is different from recreate_flavor_if_reqd().
            # Here for keypair, name and user_id are already available
            # and query api can be avoided.
            delete_kw = {'user_id': kwargs['user_id']}
            LOG.info("recreate_keypair, deleting {}:{}"
                     .format(name, delete_kw),
                     extra=self.log_extra)
            self.sc_nova_client.keypairs.delete(name, **delete_kw)
            newkeypair = self.sc_nova_client.keypairs.create(
                name, **kwargs)
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailed
        return newkeypair

    def delete_keypair(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        name, user_id = utils.keypair_deconstruct_id(rsrc.master_id)
        log_str = subcloud_rsrc.subcloud_resource_id + ' ' + \
            name + '/' + user_id
        kwargs = {}
        kwargs['user_id'] = user_id
        try:
            self.sc_nova_client.keypairs.delete(name, **kwargs)
        except novaclient_exceptions.NotFound:
            # Keypair already deleted in subcloud, carry on.
            LOG.info("Keypair {} not found in subcloud, may be already deleted"
                     .format(log_str), extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keypair {}:{} [{}] deleted".format(rsrc.id, subcloud_rsrc.id,
                 log_str), extra=self.log_extra)

    def get_all_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            # Keypair has unique id (name) per user. And, there is no API to
            # retrieve all keypairs at once. So, keypair for each user is
            # retrieved individually.
            try:
                m_resources = []
                sc_resources = []
                users = self.ks_client.users.list()
                users_with_kps = set()
                for user in users:
                    user_keypairs = self.get_keypair_resources(
                        self.m_nova_client, user.id)
                    if user_keypairs:
                        m_resources.extend(user_keypairs)
                        users_with_kps.add(user.id)
                db_resources = self.get_db_master_resources(resource_type)
                # Query the subcloud for only the users-with-keypairs in the
                # master cloud
                for userid in users_with_kps:
                    sc_user_keypairs = self.get_keypair_resources(
                        self.sc_nova_client, userid)
                    if sc_user_keypairs:
                        sc_resources.extend(sc_user_keypairs)
                LOG.info("get_all_resources: users_with_kps={}"
                         .format(users_with_kps), extra=self.log_extra)
                return m_resources, db_resources, sc_resources
            except (keystone_exceptions.connection.ConnectTimeout,
                    keystone_exceptions.ConnectFailure) as e:
                LOG.info("get_all_resources: subcloud {} is not reachable [{}]"
                         .format(self.subcloud_engine.subcloud.region_name,
                                 str(e)), extra=self.log_extra)
                return None, None, None
            except Exception as e:
                LOG.exception(e)
                return None, None, None
        else:
            return super(ComputeSyncThread, self).get_all_resources(
                resource_type)

    def get_keypair_resources(self, nc, user_id):
        keypairs = nc.keypairs.list(user_id)
        for keypair in keypairs:
            keypair._info['keypair']['user_id'] = user_id
        return keypairs

    def same_keypair(self, k1, k2):
        return (k1.name == k2.name
                and k1.type == k2.type
                and k1.fingerprint == k2.fingerprint
                and (k1._info['keypair']['user_id'] ==
                     k2._info['keypair']['user_id'])
                )

    # ---- quota_set resource operations ----
    def put_compute_quota_set(self, request, rsrc):
        project_id = request.orch_job.source_resource_id

        # Get the new global limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # Extract the user_id if there is one.
        user_id = quota_dict.pop('user_id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Force the update in case existing usage is higher.
        quota_dict['force'] = True

        # Apply the limits to the subcloud.
        self.sc_nova_client.quotas.update(project_id, user_id=user_id,
                                          **quota_dict)
        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quotas {} for tenant {} and user {}"
                 .format(quota_dict, rsrc.master_id, user_id),
                 extra=self.log_extra)

    def delete_compute_quota_set(self, request, rsrc):
        # There's tricky behaviour here, pay attention!

        # If you delete a quota-set for a tenant nova will automatically
        # delete all tenant/user quota-sets within that tenant.

        # If we delete a tenant/user quota-set in the master then we want to
        # delete it in the subcloud as well.  Nothing more is needed.
        #
        # If we delete a tenant quota-set in the master then we want to delete
        # it in the subcloud as well (to force deletion of all related
        # tenant/user quota-sets.  However, we then need to recalculate the
        # quota-set for that tenant in all the subclouds based on the current
        # usage and the default quotas.

        project_id = request.orch_job.source_resource_id

        # Get the request info from the request.
        req_info = jsonutils.loads(request.orch_job.resource_info)

        # Extract the user_id if there is one.
        user_id = req_info.pop('user_id', None)

        # Delete the quota set in the subcloud.  If user_id is None this will
        # also delete the quota-sets for all users within this project.
        self.sc_nova_client.quotas.delete(project_id, user_id)

        # Clean up the subcloud resource entry in the DB.
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if subcloud_rsrc:
            subcloud_rsrc.delete()

        # If we deleted a user/tenant quota-set we're done.
        if user_id is not None:
            return

        # If we deleted a tenant quota-set we need to recalculate the
        # tenant quota-set in the subcloud based on the default quotas
        # in the master cloud.

        # Get the new global quotas
        quota_resource = self.m_nova_client.quotas.get(project_id)
        quota_dict = quota_resource.to_dict()

        # Get rid of the "id" field before doing any calculations
        quota_dict.pop('id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Force the update in case existing usage is higher.
        quota_dict['force'] = True

        # Apply the limits to the subcloud.
        self.sc_nova_client.quotas.update(project_id, user_id=user_id,
                                          **quota_dict)

    # ---- quota_set resource operations ----
    def put_quota_class_set(self, request, rsrc):
        # Only a class_id of "default" is meaningful to nova.
        class_id = request.orch_job.source_resource_id

        # Get the new quota class limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # If this is coming from the audit we need to remove the "id" field.
        quota_dict.pop('id', None)

        # Apply the new quota class limits to the subcloud.
        self.sc_nova_client.quota_classes.update(class_id, **quota_dict)

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quota classes {} for class {}"
                 .format(quota_dict, rsrc.master_id),
                 extra=self.log_extra)

    # This will only be called by the audit code.
    def create_quota_class_set(self, request, rsrc):
        self.put_quota_class_set(request, rsrc)

    def same_quota_class(self, qc1, qc2):
        # The audit code will pass in QuotaClassSet objects, we need to
        # convert them before comparing them.
        return qc1.to_dict() == qc2.to_dict()

    def get_quota_class_resources(self, nc):
        # We only care about the "default" class since it's the only one
        # that actually affects nova.
        try:
            quota_class = nc.quota_classes.get('default')
            return [quota_class]
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_quota_class: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None
