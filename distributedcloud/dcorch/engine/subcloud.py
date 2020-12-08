# Copyright 2017-2020 Wind River
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

import threading


from dccommon import consts as dccommon_consts
from dcmanager.common import consts as dcm_consts
from dcorch.common import consts as dco_consts
from dcorch.common import context as dc_context
from dcorch.engine.sync_services.identity import IdentitySyncThread
from dcorch.engine.sync_services.sysinv import SysinvSyncThread
from dcorch.objects.subcloud import Subcloud
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# sync thread endpoint type and subclass mappings
syncthread_subclass_map = {
    dco_consts.ENDPOINT_TYPE_PLATFORM: SysinvSyncThread,
    dco_consts.ENDPOINT_TYPE_IDENTITY: IdentitySyncThread,
    dccommon_consts.ENDPOINT_TYPE_IDENTITY_OS: IdentitySyncThread
}


class SubCloudEngine(object):
    def __init__(self, context=None, name=None,
                 version=None, subcloud=None):
        """Init a subcloud

        :param context: operational context
        :param name: subcloud name, currently must match region name
        :param version: TiC software version running in subcloud
        :param subcloud: an embedded Subcloud object, persisted to DB
        """
        super(SubCloudEngine, self).__init__()
        if subcloud is not None:
            self.subcloud = subcloud
        else:
            capabilities = {}
            endpoint_type_list = dco_consts.SYNC_ENDPOINT_TYPES_LIST[:]
            capabilities.update({'endpoint_types': endpoint_type_list})
            self.subcloud = Subcloud(
                context, region_name=name, software_version=version,
                capabilities=capabilities)
            self.subcloud.create()
        self.lock = threading.Lock()     # protects the status
        self.capabilities_lock = threading.Lock()  # protects capabilities
        self.sync_threads_lock = threading.Lock()  # protects sync_threads
        self.sync_threads = []           # the individual SyncThread objects
        self.context = context if context else dc_context.get_admin_context()
        self.name = name

    def set_version(self, version):
        subcloud = Subcloud.get_by_name(self.context, self.name)
        # todo make sure we only increase the version
        subcloud.software_version = version
        subcloud.save()

    def is_managed(self):
        # is this subcloud managed
        subcloud = Subcloud.get_by_name(self.context, self.name)
        return subcloud.management_state == dcm_consts.MANAGEMENT_MANAGED

    def is_enabled(self):
        # is this subcloud enabled
        subcloud = Subcloud.get_by_name(self.context, self.name)
        # We only enable syncing if the subcloud is online and the initial
        # sync has completed.
        if subcloud.availability_status == dcm_consts.AVAILABILITY_ONLINE and \
                subcloud.initial_sync_state == \
                dco_consts.INITIAL_SYNC_STATE_COMPLETED:
            return True
        else:
            return False

    def is_ready(self):
        # is this subcloud ready for synchronization
        return self.is_managed() and self.is_enabled()

    def state_matches(self, management_state=None, availability_status=None,
                      initial_sync_state=None):
        # compare subcloud states
        match = True
        subcloud = Subcloud.get_by_name(self.context, self.name)
        if management_state is not None:
            if subcloud.management_state != management_state:
                match = False
        if match and availability_status is not None:
            if subcloud.availability_status != availability_status:
                match = False
        if match and initial_sync_state is not None:
            if subcloud.initial_sync_state != initial_sync_state:
                match = False
        return match

    def update_state(self, management_state=None, availability_status=None,
                     initial_sync_state=None):
        subcloud = Subcloud.get_by_name(self.context, self.name)
        if management_state is not None:
            subcloud.management_state = management_state
        if availability_status is not None:
            subcloud.availability_status = availability_status
        if initial_sync_state is not None:
            subcloud.initial_sync_state = initial_sync_state
        subcloud.save()

    def enable(self):
        # enable syncing for this subcloud
        for thread in self.sync_threads:
            thread.enable()

    def wake(self, endpoint_type):
        # wake specific endpoint type sync thread to process work
        if self.is_enabled():
            for thread in self.sync_threads:
                if thread.endpoint_type == endpoint_type:
                    thread.wake()

    def disable(self):
        # nothing to do here at the moment
        pass

    def delete(self):
        # first update the state of the subcloud
        self.update_state(management_state=dcm_consts.MANAGEMENT_UNMANAGED,
                          availability_status=dcm_consts.AVAILABILITY_OFFLINE)
        # shutdown, optionally deleting queued work
        while self.sync_threads:
            thread = self.sync_threads.pop()
            thread.shutdown()
        # delete this subcloud
        Subcloud.delete_subcloud_by_name(self.context, self.name)

    def initial_sync(self):
        # initial synchronization of the subcloud
        for thread in self.sync_threads:
            thread.initial_sync()

    def run_sync_audit(self, engine_id):
        # run periodic sync audit on all threads in this subcloud
        for thread in self.sync_threads:
            thread.run_sync_audit(engine_id)

    def add_sync_endpoint_type(self, endpoint_type_list):
        # add the endpoint types into subcloud capabilities
        with self.capabilities_lock:
            capabilities = self.subcloud.capabilities
            c_endpoint_type_list = capabilities.get('endpoint_types', [])

            if endpoint_type_list:
                for endpoint_type in endpoint_type_list:
                    if endpoint_type not in c_endpoint_type_list:
                        c_endpoint_type_list.append(endpoint_type)
                if capabilities.get('endpoint_types') is None:
                    # assign back if 'endpoint_types' is not in capabilities
                    capabilities['endpoint_types'] = c_endpoint_type_list
                self.subcloud.save()

        # Start threads for the endpoint types
        if endpoint_type_list:
            with self.sync_threads_lock:
                for endpoint_type in endpoint_type_list:
                    # skip creation if a thread of this endpoint type already
                    # exists
                    endpoint_thread_exist = False
                    for exist_thread in self.sync_threads:
                        if endpoint_type == exist_thread.endpoint_type:
                            endpoint_thread_exist = True
                            break
                    if endpoint_thread_exist:
                        continue

                    thread = syncthread_subclass_map[endpoint_type](
                        self, endpoint_type=endpoint_type)

                    self.sync_threads.append(thread)
                    thread.start()
                    if self.is_ready():
                        thread.enable()
                        thread.initial_sync()

    def remove_sync_endpoint_type(self, endpoint_type_list):
        # Stop threads for endpoint types to be removed
        if endpoint_type_list:
            with self.sync_threads_lock:
                for endpoint_type in endpoint_type_list:
                    for thread in self.sync_threads:
                        if thread.endpoint_type == endpoint_type:
                            self.sync_threads.remove(thread)
                            thread.shutdown()

        # remove the endpoint types from subcloud capabilities
        with self.capabilities_lock:
            capabilities = self.subcloud.capabilities
            c_endpoint_type_list = capabilities.get('endpoint_types', [])

            if endpoint_type_list and c_endpoint_type_list:
                for endpoint_type in endpoint_type_list:
                    if endpoint_type in c_endpoint_type_list:
                        c_endpoint_type_list.remove(endpoint_type)
                self.subcloud.save()
