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
# Copyright (c) 2020 Wind River Systems, Inc.
#

import eventlet
import collections  # noqa: H306
from oslo_log import log as logging
from oslo_utils import timeutils
import random

from dccommon import consts as dccommon_consts
from dcmanager.common import consts as dcm_consts
from dcorch.common import consts as dco_consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.engine import scheduler
from dcorch.engine import subcloud_lock
from dcorch.engine.sync_services.identity import IdentitySyncThread
from dcorch.engine.sync_services.sysinv import SysinvSyncThread
from dcorch.objects import subcloud


LOG = logging.getLogger(__name__)

CHECK_AUDIT_INTERVAL = 300  # frequency to check for audit work
SYNC_TIMEOUT = 600  # Timeout for subcloud sync
AUDIT_INTERVAL = 1200  # Default audit interval

# sync object endpoint type and subclass mappings
sync_object_class_map = {
    dco_consts.ENDPOINT_TYPE_PLATFORM: SysinvSyncThread,
    dco_consts.ENDPOINT_TYPE_IDENTITY: IdentitySyncThread,
    dccommon_consts.ENDPOINT_TYPE_IDENTITY_OS: IdentitySyncThread
}


class GenericSyncManager(object):
    """Manages tasks related to resource management."""

    def __init__(self, engine_id, *args, **kwargs):
        super(GenericSyncManager, self).__init__()
        self.context = context.get_admin_context()
        self.engine_id = engine_id
        # Keeps track of greenthreads we create to do the sync work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100)
        # Keeps track of greenthreads we create to do the audit work.
        self.audit_thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100)
        # this needs to map a name to a dictionary
        # stores the sync object per region per endpoint type
        self.sync_objs = collections.defaultdict(dict)
        # Track greenthreads created for each subcloud.
        self.subcloud_threads = list()
        self.subcloud_audit_threads = list()

    def init_from_db(self, context):
        subclouds = subcloud.SubcloudList.get_all(context)
        for sc in subclouds:
            self.create_sync_objects(sc.region_name, sc.capabilities)
            LOG.info('Engine id:(%s) create_sync_objects for'
                     'subcloud:%s.' % (self.engine_id, sc.region_name))

    def create_sync_objects(self, subcloud_name, capabilities):
        """Create sync object objects for the subcloud

           The objects handle the syncing of the subcloud's endpoint_types
        """

        endpoint_type_list = capabilities.get('endpoint_types', None)
        if endpoint_type_list:
            self.sync_objs[subcloud_name] = {}
            for endpoint_type in endpoint_type_list:
                LOG.info("Engine id:(%s) create %s/%s sync obj" %
                         (self.engine_id, subcloud_name, endpoint_type))
                sync_obj = sync_object_class_map[endpoint_type](subcloud_name,
                                                                endpoint_type)
                self.sync_objs[subcloud_name].update({
                    endpoint_type: sync_obj})

    def sync_job_thread(self, engine_id):
        """Perform sync request for subclouds as required."""

        while True:
            try:
                self.sync_subclouds(engine_id)
                eventlet.greenthread.sleep(5)
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception as e:
                LOG.exception(e)

    def sync_audit_thread(self, engine_id):
        """Perform sync request for subclouds as required."""

        while True:
            try:
                self.run_sync_audit(engine_id)
                eventlet.greenthread.sleep(CHECK_AUDIT_INTERVAL)
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception as e:
                LOG.exception(e)

    def sync_subclouds(self, engine_id):
        # get a list of subclouds that is online, managed and initial_sync is
        # completed, than check if subcloud_name in self.sync_objs
        # When the subcloud is managed, it will be returned in the list in the
        # next cycle. When the subcloud is unmanaged, it will not be included
        # in the list in the next cycle
        # get the subcloud/endpoint list has sync_request set to requested
        #
        subclouds = db_api.subcloud_get_all(
            self.context,
            management_state=dcm_consts.MANAGEMENT_MANAGED,
            availability_status=dcm_consts.AVAILABILITY_ONLINE,
            initial_sync_state=dco_consts.INITIAL_SYNC_STATE_COMPLETED)
        # randomize to reduce likelihood of sync_lock contention
        random.shuffle(subclouds)
        sc_names = []
        for sc in subclouds:
            if sc.region_name in self.sync_objs:
                sc_names.append(sc.region_name)
                for ept in self.sync_objs[sc.region_name].keys():
                    try:
                        self.sync_subcloud(self.context, engine_id, sc.region_name,
                                           ept, 'sync')
                    except exceptions.SubcloudSyncNotFound:
                        # The endpoint in subcloud_sync has been removed
                        LOG.info("Engine id:(%s/%s) SubcloudSyncNotFound "
                                 "remove from sync_obj endpoint_type %s" %
                                 (engine_id, sc.region_name, ept))
                        self.sync_objs[sc.region_name].pop(ept, None)

        LOG.debug('Engine id:(%s) Waiting for sync_subclouds %s to complete.'
                  % (engine_id, sc_names))
        for thread in self.subcloud_threads:
            thread.wait()

        # Clear the list of threads before next interval
        self.subcloud_threads = list()
        LOG.debug('Engine id:(%s): All subcloud syncs have completed.'
                  % engine_id)

    def _get_endpoint_sync_request(self, subcloud_name, endpoint_type):
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        return sc.sync_request.get(endpoint_type)

    @subcloud_lock.sync_subcloud
    def mutex_start_thread(self, context, engine_id, subcloud_name,
                           endpoint_type, action):
        # Double check whether still need while locked this time
        subcloud_sync = db_api.subcloud_sync_get(context, subcloud_name,
                                                 endpoint_type)
        if subcloud_sync.sync_request in [dco_consts.SYNC_STATUS_REQUESTED,
                                          dco_consts.SYNC_STATUS_FAILED]:
            thread = self.thread_group_manager.start(
                self._sync_subcloud, context, engine_id, subcloud_name,
                endpoint_type)
            self.subcloud_threads.append(thread)
        else:
            LOG.debug("mutex_start_thread Engine id: %s/%s sync not required" %
                      (engine_id, subcloud_name))

    def sync_subcloud(self, context, engine_id, subcloud_name, endpoint_type,
                      action):
        # precheck if the sync_state is still started
        subcloud_sync = db_api.subcloud_sync_get(context, subcloud_name,
                                                 endpoint_type)

        if subcloud_sync.sync_request in [dco_consts.SYNC_STATUS_REQUESTED,
                                          dco_consts.SYNC_STATUS_FAILED]:
            self.mutex_start_thread(
                context, engine_id, subcloud_name, endpoint_type, action)
        else:
            LOG.debug("Engine id: %s/%s sync not required" %
                      (engine_id, subcloud_name))

    def _sync_subcloud(self, context, engine_id, subcloud_name, endpoint_type):
        db_api.subcloud_sync_update(
            context, subcloud_name, endpoint_type,
            values={'sync_request': dco_consts.SYNC_STATUS_IN_PROGRESS})
        obj = self.sync_objs[subcloud_name][endpoint_type]
        new_state = dco_consts.SYNC_STATUS_COMPLETED
        timeout = eventlet.timeout.Timeout(SYNC_TIMEOUT)
        try:
            obj.sync(engine_id)
        except eventlet.timeout.Timeout as t:
            if t is not timeout:
                raise  # not my timeout
            new_state = dco_consts.SYNC_STATUS_FAILED
        except Exception as e:
            LOG.exception('Sync failed for %s/%s: %s',
                          subcloud_name, endpoint_type, e)
            new_state = dco_consts.SYNC_STATUS_FAILED
        finally:
            timeout.cancel()

        db_api.subcloud_sync_update(
            context, subcloud_name, endpoint_type,
            values={'sync_request': new_state})

    def add_subcloud(self, context, name, version):
        # create subcloud in DB and create the sync objects
        LOG.info('adding subcloud %(sc)s' % {'sc': name})
        capabilities = {}
        endpoint_type_list = dco_consts.SYNC_ENDPOINT_TYPES_LIST[:]
        capabilities.update({'endpoint_types': endpoint_type_list})
        sc = subcloud.Subcloud(
            context, region_name=name, software_version=version,
            capabilities=capabilities)
        sc = sc.create()
        for endpoint_type in endpoint_type_list:
            db_api.subcloud_sync_create(context, name, endpoint_type,
                                        values={'subcloud_id': sc.id})  # pylint: disable=E1101
        #  Create the sync object for this engine
        self.create_sync_objects(name, capabilities)

    def del_subcloud(self, context, subcloud_name):
        # first update the state of the subcloud
        self.update_subcloud_state(
            subcloud_name,
            management_state=dcm_consts.MANAGEMENT_UNMANAGED,
            availability_status=dcm_consts.AVAILABILITY_OFFLINE)
        # shutdown, optionally deleting queued work
        if subcloud_name not in self.sync_objs:
            LOG.error("Subcloud %s sync_objs do not exist" % subcloud_name)
        else:
            del self.sync_objs[subcloud_name]
        try:
            # delete this subcloud
            subcloud.Subcloud.delete_subcloud_by_name(context, subcloud_name)
        except Exception:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def sync_request(self, ctxt, endpoint_type):
        # Someone has enqueued a sync job. set the endpoint sync_request to
        # requested
        subclouds = db_api.subcloud_get_all(
            ctxt, management_state=dcm_consts.MANAGEMENT_MANAGED)
        for sc in subclouds:
            GenericSyncManager.set_sync_request(ctxt, sc.region_name,
                                                endpoint_type)

    @classmethod
    def set_sync_request(cls, ctxt, subcloud_name, endpoint_type):
        db_api.subcloud_sync_update(
            ctxt, subcloud_name, endpoint_type,
            values={'sync_request': dco_consts.SYNC_STATUS_REQUESTED})

    def subcloud_state_matches(self, subcloud_name,
                               management_state=None,
                               availability_status=None,
                               initial_sync_state=None):
        # compare subcloud states
        match = True
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        if management_state is not None:
            if sc.management_state != management_state:
                match = False
        if match and availability_status is not None:
            if sc.availability_status != availability_status:
                match = False
        if match and initial_sync_state is not None:
            if sc.initial_sync_state != initial_sync_state:
                match = False
        return match

    def update_subcloud_state(self, subcloud_name,
                              management_state=None,
                              availability_status=None,
                              initial_sync_state=None):
        LOG.info('updating state for subcloud %(sc)s - '
                 'management_state: %(mgmt)s '
                 'availability_status: %(avail)s '
                 'initial_sync_state: %(iss)s ' %
                 {'sc': subcloud_name, 'mgmt': management_state,
                  'avail': availability_status, 'iss': initial_sync_state})
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        if management_state is not None:
            sc.management_state = management_state
        if availability_status is not None:
            sc.availability_status = availability_status
        if initial_sync_state is not None:
            sc.initial_sync_state = initial_sync_state
        sc.save()

    def init_subcloud_sync_audit(self, subcloud_name):
        LOG.info('Initialize subcloud sync audit for '
                 'subcloud %(sc)s' %
                 {'sc': subcloud_name})

        endpoint_type_list = dco_consts.SYNC_ENDPOINT_TYPES_LIST[:]
        for endpoint_type in endpoint_type_list:
            db_api.subcloud_sync_update(
                self.context, subcloud_name, endpoint_type,
                values={'audit_status': dco_consts.AUDIT_STATUS_NONE,
                        'sync_status_reported': dco_consts.SYNC_STATUS_NONE,
                        'sync_status_report_time': None,
                        'last_audit_time': None})

    def enable_subcloud(self, context, subcloud_name):
        LOG.info('enabling subcloud %(sc)s' % {'sc': subcloud_name})
        if subcloud_name in self.sync_objs:
            for sync_obj in self.sync_objs[subcloud_name].values():
                LOG.info('Engine id: %(id)s enabling sync '
                         'thread subcloud %(sc)s' %
                         {'sc': subcloud_name, 'id': self.engine_id})
                sync_obj.enable()
        else:
            LOG.error("enable_subcloud No sync objects for subcloud:%s" %
                      subcloud_name)

    def disable_subcloud(self, context, subcloud_name):
        LOG.info('disabling subcloud %(sc)s' % {'sc': subcloud_name})
        # nothing to do here at the moment
        pass

    def is_subcloud_managed(self, subcloud_name):
        # is this subcloud managed
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        return sc.management_state == dcm_consts.MANAGEMENT_MANAGED

    def is_subcloud_enabled(self, subcloud_name):
        # is this subcloud enabled
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        # We only enable syncing if the subcloud is online and the initial
        # sync has completed.
        if (sc.availability_status == dcm_consts.AVAILABILITY_ONLINE and
           sc.initial_sync_state == dco_consts.INITIAL_SYNC_STATE_COMPLETED):
            return True
        else:
            return False

    def is_subcloud_ready(self, subcloud_name):
        # is this subcloud ready for synchronization
        return self.is_subcloud_managed(subcloud_name) and \
            self.is_subcloud_enabled(subcloud_name)

    def add_subcloud_sync_endpoint_type(self, context, subcloud_name,
                                        endpoint_type_list=None):

        # TODO(jkung): This method is currently only required by
        # stx-openstack and is to be integrated with stx-openstack when
        # that feature is enabled.

        LOG.info("add_subcloud_sync_endpoint_type subcloud_name=%s "
                 "endpoint_type_list=%s" %
                 (subcloud_name, endpoint_type_list))

        sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
        capabilities = sc.capabilities
        c_endpoint_type_list = capabilities.get('endpoint_types', [])

        # Update the DB first
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                if endpoint_type not in c_endpoint_type_list:
                    c_endpoint_type_list.append(endpoint_type)
            if capabilities.get('endpoint_types') is None:
                # assign back if 'endpoint_types' is not in capabilities
                capabilities['endpoint_types'] = c_endpoint_type_list
            sc.capabilities = capabilities
            sc.save()

        # Create objects for the endpoint types
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                # Check whether sync endpoint already exists
                try:
                    subcloud_sync = db_api.subcloud_sync_get(
                        context, subcloud_name,
                        endpoint_type)

                    if subcloud_sync:
                        LOG.info("subcloud_sync subcloud=%s "
                                 "endpoint_type=%s already exists" %
                                 (subcloud_name, endpoint_type))
                        continue
                except exceptions.SubcloudSyncNotFound:
                    pass

                # skip creation if a sync_obj of this endpoint type already
                # exists
                sync_obj = self.sync_objs[subcloud_name].get(
                    endpoint_type == endpoint_type)
                if not sync_obj:
                    LOG.info("add_subcloud_sync_endpoint_type "
                             "subcloud_name=%s, sync_obj add=%s" %
                             (subcloud_name, endpoint_type))
                    sync_obj = sync_object_class_map[endpoint_type](
                        subcloud_name, endpoint_type=endpoint_type)
                    self.sync_objs[subcloud_name].update(
                        {endpoint_type: sync_obj})

                # create the subcloud_sync !!!
                db_api.subcloud_sync_create(
                    context, subcloud_name, endpoint_type,
                    values={'subcloud_id': sc.id})

                if self.is_subcloud_ready(subcloud_name):
                    sync_obj.enable()
                    sync_obj.initial_sync()

    def remove_subcloud_sync_endpoint_type(self, context, subcloud_name,
                                           endpoint_type_list=None):

        # TODO(jkung): This method is currently only required by
        # stx-openstack and is to be integrated with stx-openstack when
        # that feature is enabled and remove action performed.
        # The subcloud_sync delete can be more graceful by ensuring the
        # sync object is updated for each engine on delete.

        LOG.info("remove_subcloud_sync_endpoint_type subcloud_name=%s "
                 "endpoint_type_list=%s" %
                 (subcloud_name, endpoint_type_list))

        # Remove sync_objs and subcloud_sync for endpoint types to be removed
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                self.sync_objs[subcloud_name].pop(endpoint_type, None)

                try:
                    db_api.subcloud_sync_delete(
                        context, subcloud_name, endpoint_type)
                except exceptions.SubcloudSyncNotFound:
                    pass

        # remove the endpoint types from subcloud capabilities
        sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
        capabilities = sc.capabilities
        c_endpoint_type_list = capabilities.get('endpoint_types', [])

        if endpoint_type_list and c_endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                if endpoint_type in c_endpoint_type_list:
                    c_endpoint_type_list.remove(endpoint_type)
            sc.capabilities = capabilities
            sc.save()

    def update_subcloud_version(self, context, subcloud_name, sw_version):
        try:
            sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
            sc.software_version = sw_version
            sc.save()
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def initial_sync(self, context, subcloud_name):
        LOG.info('Initial sync subcloud %(sc)s %(id)s' %
                 {'sc': subcloud_name, 'id': self.engine_id})
        # initial synchronization of the subcloud
        if subcloud_name in self.sync_objs:
            # self.sync_objs stores the sync object per endpoint
            for sync_obj in self.sync_objs[subcloud_name].values():
                sync_obj.initial_sync()
        else:
            LOG.info('Initial sync subcloud %(sc)s '
                     'sync_objs not found...creating' %
                     {'sc': subcloud_name})
            capabilities = {}
            endpoint_type_list = dco_consts.SYNC_ENDPOINT_TYPES_LIST[:]
            capabilities.update({'endpoint_types': endpoint_type_list})
            self.create_sync_objects(subcloud_name, capabilities)
            if subcloud_name in self.sync_objs:
                # self.sync_objs stores the sync object per endpoint
                for sync_obj in self.sync_objs[subcloud_name].values():
                    sync_obj.initial_sync()
            else:
                LOG.error('Initial sync subcloud %(sc)s '
                          'sync_objs not found' %
                          {'sc': subcloud_name})

    @subcloud_lock.sync_subcloud
    def audit_subcloud(self, context, engine_id, subcloud_name, endpoint_type,
                       action):
        subcloud_sync = db_api.subcloud_sync_get(context, subcloud_name,
                                                 endpoint_type)
        # check if the last audit time is equal or greater than the audit
        # interval ( only if the status is completed
        # if status is failed, go ahead with audit
        # restart audit if process death while audit is in progress
        audit = False
        if subcloud_sync.audit_status in [dco_consts.AUDIT_STATUS_COMPLETED,
                                          dco_consts.AUDIT_STATUS_IN_PROGRESS]:
            if subcloud_sync.last_audit_time:
                delta = timeutils.delta_seconds(
                    subcloud_sync.last_audit_time, timeutils.utcnow())
                # Audit interval
                if delta >= AUDIT_INTERVAL:
                    audit = True
            else:
                audit = True
        elif subcloud_sync.audit_status in [dco_consts.AUDIT_STATUS_NONE,
                                            dco_consts.AUDIT_STATUS_FAILED]:
            audit = True

        if audit:
            thread = self.thread_group_manager.start(
                self._audit_subcloud, engine_id, subcloud_name, endpoint_type)
            self.subcloud_audit_threads.append(thread)

    def _audit_subcloud(self, engine_id, subcloud_name, endpoint_type):
        # The last_audit_time is set up front in order to ensure synchronous
        # audit_subcloud() check for in progress and last_audit_time
        db_api.subcloud_sync_update(
            context, subcloud_name, endpoint_type,
            values={'audit_status': dco_consts.AUDIT_STATUS_IN_PROGRESS,
                    'last_audit_time': timeutils.utcnow()})
        obj = self.sync_objs[subcloud_name][endpoint_type]
        new_state = dco_consts.AUDIT_STATUS_COMPLETED
        timeout = eventlet.timeout.Timeout(SYNC_TIMEOUT)
        try:
            obj.run_sync_audit(engine_id)
        except eventlet.timeout.Timeout as t:
            if t is not timeout:
                raise  # not my timeout
            new_state = dco_consts.AUDIT_STATUS_FAILED
        except Exception as e:
            LOG.exception('Audit failed for %s/%s: %s',
                          subcloud_name, endpoint_type, e)
            new_state = dco_consts.AUDIT_STATUS_FAILED
        finally:
            timeout.cancel()

        db_api.subcloud_sync_update(
            context, subcloud_name, endpoint_type,
            values={'audit_status': new_state})

    def run_sync_audit(self, engine_id):
        LOG.info('run_sync_audit %(id)s' % {'id': engine_id})
        # get a list of subclouds that are enabled
        subclouds = db_api.subcloud_get_all(
            self.context,
            management_state=dcm_consts.MANAGEMENT_MANAGED,
            availability_status=dcm_consts.AVAILABILITY_ONLINE,
            initial_sync_state=dco_consts.INITIAL_SYNC_STATE_COMPLETED)

        # randomize to reduce likelihood of sync_lock contention
        random.shuffle(subclouds)
        for sc in subclouds:
            if sc.region_name in list(self.sync_objs.keys()):
                for e in self.sync_objs[sc.region_name].keys():
                    LOG.debug("Attempt audit_subcloud: %s/%s/%s",
                              engine_id, sc.region_name, e)
                    self.audit_subcloud(self.context, engine_id,
                                        sc.region_name, e, 'audit')
            else:
                # In this case, distribution of sync objects are
                # to each worker.  If needed in future implementation,
                # it is possible to distribute sync_objs to certain workers.
                LOG.info('Run sync audit sync subcloud %(sc)s '
                         'sync_objs not found...creating' %
                         {'sc': sc.region_name})
                capabilities = {}
                endpoint_type_list = dco_consts.SYNC_ENDPOINT_TYPES_LIST[:]
                capabilities.update({'endpoint_types': endpoint_type_list})
                self.create_sync_objects(sc.region_name, capabilities)
                # self.sync_objs stores the sync object per endpoint
                if sc.region_name in list(self.sync_objs.keys()):
                    for e in self.sync_objs[sc.region_name].keys():
                        LOG.debug("Attempt audit_subcloud: %s/%s/%s",
                                  engine_id, sc.region_name, e)
                        self.audit_subcloud(self.context, engine_id,
                                            sc.region_name, e, 'audit')
                else:
                    LOG.error('Run sync audit subcloud %(sc)s '
                              'sync_objs not found' %
                              {'sc': sc.region_name})

        LOG.debug('Engine id:(%s) Waiting for audit_subclouds to complete.'
                  % engine_id)
        for thread in self.subcloud_audit_threads:
            thread.wait()

        # Clear the list of threads before next interval
        self.subcloud_audit_threads = list()
        LOG.info('Engine id:(%s): All subcloud audit have completed.'
                 % engine_id)
