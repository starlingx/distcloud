# Copyright 2017 Wind River
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

from dcmanager.common import consts as dcm_consts
from dcorch.common import consts as dco_consts
from dcorch.engine.sync_services.identity import IdentitySyncThread
from dcorch.engine.sync_services.sysinv import SysinvSyncThread
from dcorch.objects.subcloud import Subcloud
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# sync thread endpoint type and subclass mappings
syncthread_subclass_map = {
    dco_consts.ENDPOINT_TYPE_PLATFORM: SysinvSyncThread,
    dco_consts.ENDPOINT_TYPE_IDENTITY: IdentitySyncThread,
    dco_consts.ENDPOINT_TYPE_IDENTITY_OS: IdentitySyncThread
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
            endpoint_type_list = dco_consts.ENDPOINT_TYPES_LIST[:]
            # patching is handled by dcmanager
            endpoint_type_list.remove(dco_consts.ENDPOINT_TYPE_PATCHING)
            capabilities.update({'endpoint_types': endpoint_type_list})
            self.subcloud = Subcloud(
                context, region_name=name, software_version=version,
                capabilities=capabilities)
            self.subcloud.create()
        self.lock = threading.Lock()     # protects the status
        self.capabilities_lock = threading.Lock()  # protects capabilities
        self.sync_threads_lock = threading.Lock()  # protects sync_threads
        self.sync_threads = []           # the individual SyncThread objects

    def set_version(self, version):
        # todo make sure we only increase the version
        self.subcloud.software_version = version
        self.subcloud.save()

    def spawn_sync_threads(self):
        # spawn the threads that actually handle syncing this subcloud

        capabilities = self.subcloud.capabilities
        # start sync threads
        endpoint_type_list = capabilities.get('endpoint_types', None)
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                thread = syncthread_subclass_map[endpoint_type](self)
                self.sync_threads.append(thread)
                thread.start()

    def is_managed(self):
        # is this subcloud managed
        self.lock.acquire()
        managed = self.subcloud.management_state
        self.lock.release()
        return managed == dcm_consts.MANAGEMENT_MANAGED

    def is_enabled(self):
        # is this subcloud enabled
        self.lock.acquire()
        status = self.subcloud.availability_status
        self.lock.release()
        return status == dcm_consts.AVAILABILITY_ONLINE

    def is_ready(self):
        # is this subcloud ready for synchronization
        return self.is_managed() and self.is_enabled()

    def enable(self):
        # set subcloud availability to online
        self.lock.acquire()
        self.subcloud.management_state = dcm_consts.MANAGEMENT_MANAGED
        self.subcloud.availability_status = dcm_consts.AVAILABILITY_ONLINE
        self.subcloud.save()
        self.lock.release()
        for thread in self.sync_threads:
            thread.enable()

    def wake(self, endpoint_type):
        # wake specific endpoint type sync thread to process work
        if self.is_enabled():
            for thread in self.sync_threads:
                if thread.endpoint_type == endpoint_type:
                    thread.wake()

    def disable(self):
        # set subcloud availability to offline
        self.lock.acquire()
        self.subcloud.management_state = dcm_consts.MANAGEMENT_UNMANAGED
        self.subcloud.availability_status = dcm_consts.AVAILABILITY_OFFLINE
        self.subcloud.save()
        self.lock.release()

    def shutdown(self):
        # shutdown, optionally deleting queued work
        self.disable()
        while self.sync_threads:
            thread = self.sync_threads.pop()
            thread.shutdown()

    def delete(self):
        # delete this subcloud
        self.shutdown()
        self.subcloud.delete()

    def initial_sync(self):
        # initial synchronization of the subcloud
        for thread in self.sync_threads:
            thread.initial_sync()

    def run_sync_audit(self):
        # run periodic sync audit on all threads in this subcloud
        if self.is_enabled():
            for thread in self.sync_threads:
                thread.run_sync_audit()

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
