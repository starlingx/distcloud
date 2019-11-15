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

from oslo_log import log as logging

from dcorch.common import exceptions
from dcorch.engine.subcloud import SubCloudEngine
from dcorch.objects import subcloud

LOG = logging.getLogger(__name__)


class GenericSyncManager(object):
    """Manages tasks related to resource management."""

    def __init__(self, *args, **kwargs):
        super(GenericSyncManager, self).__init__()
        self.subcloud_engines = {}

    def init_from_db(self, context):
        subclouds = subcloud.SubcloudList.get_all(context)
        for sc in subclouds:
            engine = SubCloudEngine(subcloud=sc)
            LOG.info('loading subcloud %(sc)s' %
                     {'sc': sc.region_name})
            self.subcloud_engines[sc.region_name] = engine
            engine.spawn_sync_threads()

    def add_subcloud(self, context, name, version):
        LOG.info('adding subcloud %(sc)s' % {'sc': name})
        subcloud_engine = SubCloudEngine(
            context=context, name=name, version=version)
        self.subcloud_engines[name] = subcloud_engine
        subcloud_engine.spawn_sync_threads()

    def del_subcloud(self, context, subcloud_name):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
            LOG.info('deleting subcloud %(sc)s' % {'sc': subcloud_name})
            subcloud_engine.delete()
            del self.subcloud_engines[subcloud_name]
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def sync_request(self, ctxt, endpoint_type):
        # Someone has enqueued a sync job.  Wake the subcloud engines.
        for subcloud_engine in self.subcloud_engines.values():
            subcloud_engine.wake(endpoint_type)

    def enable_subcloud(self, context, subcloud_name):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
            LOG.info('enabling subcloud %(sc)s' % {'sc': subcloud_name})
            subcloud_engine.enable()
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def disable_subcloud(self, context, subcloud_name):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
            LOG.info('disabling subcloud %(sc)s' % {'sc': subcloud_name})
            subcloud_engine.disable()
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def add_subcloud_sync_endpoint_type(self, context, subcloud_name,
                                        endpoint_type_list=None):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

        LOG.info('adding sync endpoint type for subcloud %(sc)s' %
                 {'sc': subcloud_name})
        try:
            subcloud_engine.add_sync_endpoint_type(endpoint_type_list)
        except Exception:
            subcloud_engine.remove_sync_endpoint_type(endpoint_type_list)
            raise

    def remove_subcloud_sync_endpoint_type(self, context, subcloud_name,
                                           endpoint_type_list=None):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
            LOG.info('removing sync endpoint type for subcloud %(sc)s' %
                     {'sc': subcloud_name})
            subcloud_engine.remove_sync_endpoint_type(endpoint_type_list)
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def update_subcloud_version(self, context, subcloud_name, sw_version):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
            LOG.info('updating subcloud %(sc)s version to %(ver)s' %
                     {'sc': subcloud_name, 'ver': sw_version})
            subcloud_engine.set_version(sw_version)
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def initial_sync(self, context, subcloud_name):
        try:
            subcloud_engine = self.subcloud_engines[subcloud_name]
            LOG.info('Initial sync subcloud %(sc)s' % {'sc': subcloud_name})
            subcloud_engine.initial_sync()
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def run_sync_audit(self):
        for subcloud_engine in self.subcloud_engines.values():
            subcloud_engine.run_sync_audit()
