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
from dcorch.engine.sync_thread import SyncThread
from dcorch.objects.subcloud import Subcloud
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


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
            self.subcloud = Subcloud(
                context, region_name=name, software_version=version)
            self.subcloud.create()
        self.lock = threading.Lock()     # protects the status
        self.sync_threads = []           # the individual SyncThread objects

    def set_version(self, version):
        # todo make sure we only increase the version
        self.subcloud.software_version = version
        self.subcloud.save()

    def spawn_sync_threads(self):
        # spawn the threads that actually handle syncing this subcloud
        for subclass in SyncThread.__subclasses__():
            thread = subclass(self)
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
