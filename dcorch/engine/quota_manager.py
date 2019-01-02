# Copyright 2016 Ericsson AB
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

import collections
import copy
import re
from six.moves.queue import Queue
import threading
import time

from oslo_config import cfg
from oslo_log import log as logging

from dcorch.common import consts
from dcorch.common import context
from dcorch.common import endpoint_cache
from dcorch.common import exceptions
from dcorch.common.i18n import _
from dcorch.common import manager
from dcorch.common import utils
from dcorch.db import api as db_api
from dcorch.drivers.openstack import sdk
from dcorch.engine import dc_orch_lock

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# Projects are synced batch by batch. Below configuration defines
# number of projects in each batch
batch_opts = [
    cfg.IntOpt('batch_size',
               default=3,
               help='Batch size number of projects will be synced at a time')
]

batch_opt_group = cfg.OptGroup('batch')
cfg.CONF.register_group(batch_opt_group)
cfg.CONF.register_opts(batch_opts, group=batch_opt_group)
TASK_TYPE = 'quota_sync'


class QuotaManager(manager.Manager):
    """Manages tasks related to quota management"""

    # Static variables used to store cached usage information and the lock
    # that protects their access.
    # It's either this or pass references to the QuotaManager object
    # down into the guts of the SyncThread class.
    usage_lock = threading.Lock()
    # Each of the following is a dict where the keys are project-ID/user-ID
    # tuples.  (Where the user-ID can be None for project-only usage.)
    total_project_usages = {}
    regions_usage_dict = {}

    def __init__(self, *args, **kwargs):
        LOG.debug(_('QuotaManager initialization...'))

        super(QuotaManager, self).__init__(service_name="quota_manager",
                                           *args, **kwargs)
        self.context = context.get_admin_context()
        self.endpoints = endpoint_cache.EndpointCache()

        # This lock is used to ensure we only have one quota sync audit at
        # a time.  For better efficiency we could use per-project locks
        # and/or the ReaderWriterLock from the "fastener" package.
        self.quota_audit_lock = threading.Lock()

    @classmethod
    def calculate_subcloud_project_quotas(cls, project_id, user_id,
                                          new_global_quotas, subcloud):
        # Someone has changed the quotas for a project, so we need to
        # calculate the new quotas in each subcloud.

        # First, grab a copy of the usage from the last quota audit.
        with cls.usage_lock:
            regions_usage_dict = copy.deepcopy(
                cls.regions_usage_dict.get((project_id, user_id), {}))
            total_project_usages = copy.deepcopy(
                cls.total_project_usages.get((project_id, user_id), {}))

        # Calculate the remaining global project limit based on the new quotas
        # and the total usage for the project across all subclouds.
        unused_global_limits = collections.Counter(
            new_global_quotas) - collections.Counter(total_project_usages)

        # Now get the region-specific usage and trim it back to just the dict
        # keys present in the new quotas.
        try:
            region_usage = regions_usage_dict[subcloud]
            region_usage = dict([(k, region_usage[k])
                                 for k in new_global_quotas])
        except KeyError:
            # From startup until the quota audit runs we'll end up here.
            region_usage = {}

        # Now add the region-specific usage to the global remaining limits.
        region_new_limits = dict(unused_global_limits +
                                 collections.Counter(region_usage))

        return region_new_limits

    def get_projects_users_with_modified_quotas(self):
        # get the list of project/user tuples that have modified quotas
        project_user_list = set([])
        os_client = sdk.OpenStackDriver(consts.VIRTUAL_MASTER_CLOUD)
        try:
            quotas = os_client.nova_client.nova_client.quotas.list()
            project_user_quotas = quotas['project_user_quotas']
            for project_user_quota in project_user_quotas:
                project_id = project_user_quota['project_id']
                user_quotas = project_user_quota['user_quotas']
                for user_quota in user_quotas:
                    user_id = user_quota['user_id']
                    project_user_list.add((project_id, user_id))
        except AttributeError:
            # Dealing with novaclient that doesn't have quotas.list(),
            # so just ignore project/user quotas.
            pass
        return list(project_user_list)

    def periodic_balance_all(self, engine_id):
        LOG.info("periodically balance quota for all keystone tenants")
        lock = dc_orch_lock.sync_lock_acquire(engine_id, TASK_TYPE,
                                              self.quota_audit_lock)
        if not lock:
            LOG.error("Not able to acquire lock for %(task_type)s, may"
                      " be Previous sync job has not finished yet, "
                      "Aborting this run at: %(time)s ",
                      {'task_type': TASK_TYPE,
                       'time': time.strftime("%c")}
                      )
            return
        LOG.info("Successfully acquired lock")
        projects_thread_list = []

        # Generate a list of project_id/user_id tuples that need to have their
        # quotas updated.  This is basically all projects, and the
        # projects/users that have modified quotas.
        # Where user_id is None, this represents the project quotas.  Where
        # user_id is specified, it represents the project/user quotas.  (This
        # is only applicable to nova.)
        project_list = sdk.OpenStackDriver().get_enabled_projects()
        project_user_list = [(project, None) for project in project_list]
        project_user_mod_list = self.get_projects_users_with_modified_quotas()
        project_user_list.extend(project_user_mod_list)

        # Remove any global cache entries for project_id/user_id tuples that
        # aren't in the list to be updated.  (They'll get updated on-demand.)
        with QuotaManager.usage_lock:
            # The same keys should be in QuotaManager.total_project_usages
            # so we only need to look at one of them.
            to_delete = [k for k in QuotaManager.regions_usage_dict
                         if k not in project_user_mod_list]
            for k in to_delete:
                del QuotaManager.regions_usage_dict[k]
                del QuotaManager.total_project_usages[k]

        # Iterate through project list and call sync project for each project
        # using threads
        # Divide list of projects into batches and perfrom quota sync
        # for one batch at a time.
        for current_batch_projects_users in utils.get_batch_projects(
                cfg.CONF.batch.batch_size, project_user_list):
            # "current_batch_projects_users" may have some None entries that
            # we don't want to iterate over.
            current_batch_projects_users = [
                x for x in current_batch_projects_users if x is not None]
            LOG.info("Syncing quota for current batch with projects: %s",
                     current_batch_projects_users)
            for project_id, user_id in current_batch_projects_users:
                if project_id:
                    thread = threading.Thread(
                        target=self.quota_sync_for_project,
                        args=(project_id, user_id,))
                    projects_thread_list.append(thread)
                    thread.start()
                # Wait for all the threads to complete
                # the job(sync all projects quota)
                for current_thread in projects_thread_list:
                    current_thread.join()
        dc_orch_lock.sync_lock_release(engine_id, TASK_TYPE,
                                       self.quota_audit_lock)

    def read_quota_usage(self, project_id, user_id, region, usage_queue):
        # Writes usage dict to the Queue in the following format
        # {'region_name': (<nova_usages>, <neutron_usages>, <cinder_usages>)}
        LOG.info("Reading quota usage for project: %(project_id)s and user: "
                 "%(user_id)s in %(region)s",
                 {'project_id': project_id, 'user_id': user_id,
                  'region': region}
                 )
        os_client = sdk.OpenStackDriver(region)
        (nova_usage, neutron_usage, cinder_usage) = \
            os_client.get_resource_usages(project_id, user_id)
        total_region_usage = collections.defaultdict(dict)
        # region_usage[0], region_usage[1], region_usage[3] are
        # nova, neutron & cinder usages respectively
        if nova_usage:
            total_region_usage.update(nova_usage)
        if neutron_usage:
            total_region_usage.update(neutron_usage)
        if cinder_usage:
            total_region_usage.update(cinder_usage)
        usage_queue.put({region: total_region_usage})

    def get_summation(self, regions_dict):
        # Adds resources usages from different regions
        single_region = {}
        resultant_dict = collections.Counter()
        for current_region in regions_dict:
            single_region[current_region] = collections.Counter(
                regions_dict[current_region])
            resultant_dict += single_region[current_region]
        return resultant_dict

    def get_tenant_quota_limits_region(self, project_id, user_id, region):
        # returns quota limits for region  in the following format
        # {<nova_limits>, <neutron_limits>, <cinder_limits>}
        LOG.info("Reading quota limits for project: %(project_id)s and user: "
                 "%(user_id)s in %(region)s",
                 {'project_id': project_id, 'user_id': user_id,
                  'region': region}
                 )
        os_client = sdk.OpenStackDriver(region)
        (nova_limits, neutron_limits, cinder_limits) = \
            os_client.get_quota_limits(project_id, user_id)
        limits = {}
        limits.update(nova_limits)
        limits.update(neutron_limits)
        limits.update(cinder_limits)
        return limits

    def _get_dc_orch_project_limit(self, project_id):
        # Returns DC Orchestrator project limit for a project.
        dc_orch_limits_for_project = collections.defaultdict(dict)
        try:
            # checks if there are any quota limit in DB for a project
            limits_from_db = db_api.quota_get_all_by_project(self.context,
                                                             project_id)
        except exceptions.ProjectQuotaNotFound:
            limits_from_db = {}
        for current_resource in CONF.dc_orch_global_limit.items():
            resource = re.sub('quota_', '', current_resource[0])
            # If resource limit in DB, then use it or else use limit
            # from conf file
            if resource in limits_from_db:
                dc_orch_limits_for_project[resource] = limits_from_db[
                    resource]
            else:
                dc_orch_limits_for_project[resource] = current_resource[1]
        return dc_orch_limits_for_project

    def _arrange_quotas_by_service_name(self, region_new_limit):
        # Returns a dict of resources with limits arranged by service name
        resource_with_service = collections.defaultdict(dict)
        resource_with_service['nova'] = collections.defaultdict(dict)
        resource_with_service['cinder'] = collections.defaultdict(dict)
        resource_with_service['neutron'] = collections.defaultdict(dict)
        for limit in region_new_limit:
            if limit in consts.NOVA_QUOTA_FIELDS:
                resource_with_service['nova'].update(
                    {limit: region_new_limit[limit]})
            elif limit in consts.CINDER_QUOTA_FIELDS:
                resource_with_service['cinder'].update(
                    {limit: region_new_limit[limit]})
            elif limit in consts.NEUTRON_QUOTA_FIELDS:
                resource_with_service['neutron'].update(
                    {limit: region_new_limit[limit]})
        return resource_with_service

    def update_quota_limits(self, project_id, user_id, region_new_limit,
                            current_region):
        # Updates quota limit for a project with new calculated limit
        os_client = sdk.OpenStackDriver(current_region)
        os_client.write_quota_limits(project_id, user_id, region_new_limit)

    def quota_usage_update(self, project_id, user_id):
        # Update the quota usage for the specified project/user
        regions_usage_dict = self.get_tenant_quota_usage_per_region(project_id,
                                                                    user_id)
        if not regions_usage_dict:
            # Skip syncing for the project if not able to read regions usage
            LOG.error("Error reading regions usage for the project: "
                      "'%(project)s' and user: '%(user)s'. Aborting, continue "
                      "with next project/user.",
                      {'project': project_id, 'user': user_id})
            return None, None

        # We want to return the original per-subcloud usage, so make a
        # copy for us to mangle.
        regions_usage_dict_copy = copy.deepcopy(regions_usage_dict)

        # We don't want to sum up the subcloud usage of resource types that
        # are managed by dcorch so delete them from all regions except
        # the master one.
        for region in regions_usage_dict_copy:
            if region == consts.VIRTUAL_MASTER_CLOUD:
                continue
            for quota in consts.QUOTAS_FOR_MANAGED_RESOURCES:
                regions_usage_dict_copy[region].pop(quota, None)

        # Add up the usage for this project/user across all subclouds.
        total_project_usages = dict(
            self.get_summation(regions_usage_dict_copy))

        # Save the global and per-region usage for use when
        # modifying quotas later
        with QuotaManager.usage_lock:
            # Use the project/user tuple as the dict key.
            # 'user_id' will be None for the overall project usage.
            QuotaManager.total_project_usages[(project_id, user_id)] = \
                copy.deepcopy(total_project_usages)
            QuotaManager.regions_usage_dict[(project_id, user_id)] = \
                copy.deepcopy(regions_usage_dict)

        return total_project_usages, regions_usage_dict

    def quota_sync_for_project(self, project_id, user_id):
        # Sync quota limits for the project according to below formula
        # Global remaining limit =
        #   DC Orchestrator global limit - Summation of usages
        #                          in all the regions
        # New quota limit = Global remaining limit + usage in that region
        LOG.info("Quota sync called for project: %(project)s user: %(user)s",
                 {'project': project_id, 'user': user_id})
        regions_thread_list = []
        # Retrieve regions for the project.  This is also done in
        # get_tenant_quota_usage_per_region() so we may be able to only do
        # it once. Would have to consider the failure  modes though.
        os_driver = sdk.OpenStackDriver()
        region_lists = os_driver.get_all_regions_for_project(
            project_id)

        total_project_usages, regions_usage_dict = self.quota_usage_update(
            project_id, user_id)
        if ((total_project_usages, regions_usage_dict) == (None, None)):
            return

        # Get the global limit for this project from the master subcloud.
        dc_orch_global_limits = self.get_overall_tenant_quota_limits(
            project_id, user_id)
        # Calculate how much of the various limits have not yet been used.
        unused_global_limits = collections.Counter(
            dc_orch_global_limits) - collections.Counter(total_project_usages)

        # Remove the master region from the list.  Its quotas should already
        # be up to date for managed resources.
        region_lists.remove(consts.VIRTUAL_MASTER_CLOUD)

        # (NOTE: knasim-wrs): The Master Cloud's Project ID and User ID
        # dont mean anything for the subcloud, so we need to first resolve
        # the project name, and username and then determine the specific
        # IDs for that subcloud
        qproject = os_driver.get_project_by_id(project_id)
        quser = os_driver.get_user_by_id(user_id)

        for current_region in region_lists:
            # Calculate the new limit for this region.
            region_new_limits = dict(
                unused_global_limits + collections.Counter(
                    regions_usage_dict[current_region]))
            # Reformat the limits
            region_new_limits = self._arrange_quotas_by_service_name(
                region_new_limits)
            # Update the subcloud with the new limit
            try:
                # First find this project and user in this subcloud
                sc_user_id = None
                sc_os_driver = sdk.OpenStackDriver(current_region)
                sc_project = sc_os_driver.get_project_by_name(qproject.name)
                if not sc_project:
                    LOG.info("Cannot find project %s in subcloud %s. Skipping "
                             "quota sync for this project on subcloud",
                             qproject.name, current_region)
                    continue
                sc_project_id = sc_project.id
                if quser:
                    sc_user = sc_os_driver.get_user_by_name(quser.name)
                    sc_user_id = getattr(sc_user, 'id', None)
            except Exception as e:
                LOG.error("quota sync %s: %s", current_region, e.message)
                continue

            thread = threading.Thread(target=self.update_quota_limits,
                                      args=(sc_project_id, sc_user_id,
                                            region_new_limits,
                                            current_region,))
            regions_thread_list.append(thread)
            thread.start()

        # Wait for all the threads to update quota
        for current_thread in regions_thread_list:
            current_thread.join()

    def get_overall_tenant_quota_limits(self, project_id, user_id):
        # Return quota limits in the master cloud.  These are the overall
        # quota limits for the whole cloud.
        return self.get_tenant_quota_limits_region(project_id, user_id,
                                                   consts.VIRTUAL_MASTER_CLOUD)

    def get_tenant_quota_usage_per_region(self, project_id, user_id):
        # Return quota usage dict with keys as region name & values as usages.
        # Calculates the usage from each region concurrently using threads.
        os_driver = sdk.OpenStackDriver()
        # Retrieve regions for the project
        region_lists = os_driver.get_all_regions_for_project(
            project_id)
        usage_queue = Queue()
        regions_usage_dict = collections.defaultdict(dict)
        regions_thread_list = []
        qproject = os_driver.get_project_by_id(project_id)
        quser = os_driver.get_user_by_id(user_id)

        for current_region in region_lists:
            # First find this project and user in this subcloud
            try:
                sc_user_id = None
                sc_os_driver = sdk.OpenStackDriver(current_region)
                sc_project = sc_os_driver.get_project_by_name(qproject.name)
                if not sc_project:
                    LOG.info("Cannot find project %s in subcloud %s. Skipping "
                             "quota usage for this project on subcloud",
                             qproject.name, current_region)
                    continue
                sc_project_id = sc_project.id
                if quser:
                    sc_user = sc_os_driver.get_user_by_name(quser.name)
                    sc_user_id = getattr(sc_user, 'id', None)
            except Exception as e:
                LOG.error("quota usage %s: %s", current_region, e.message)
                continue

            thread = threading.Thread(target=self.read_quota_usage,
                                      args=(sc_project_id, sc_user_id,
                                            current_region, usage_queue))
            regions_thread_list.append(thread)
            thread.start()
        # Wait for all the threads to finish reading usages
        for current_thread in regions_thread_list:
            current_thread.join()
        # Check If all the regions usages are read
        if len(region_lists) == usage_queue.qsize():
            for i in range(usage_queue.qsize()):
                # Read Queue
                current_region_data = usage_queue.get()
                regions_usage_dict.update(current_region_data)
        return regions_usage_dict

    def get_usage_for_project_and_user(self, endpoint_type,
                                       project_id, user_id):
        # Returns cached quota usage for a project and user.  If there
        # is no cached usage information then update the cache.

        with QuotaManager.usage_lock:
            # First, try to get a copy of the usage from the last quota audit.
            total_project_usages = copy.deepcopy(
                QuotaManager.total_project_usages.get((project_id, user_id),
                                                      None))
        if total_project_usages is None:
            # This project/user doesn't have any cached usage information,
            # so we need to query it.
            try:
                total_project_usages, regions_usage_dict = \
                    self.quota_usage_update(project_id, user_id)
            except exceptions.ProjectNotFound:
                total_project_usages = {}

        # "total_project_usages" includes fields from multiple
        # endpoint types, so we need to figure out which ones we want.
        desired_fields = consts.ENDPOINT_QUOTA_MAPPING[endpoint_type]
        usage_dict = {}
        for k, v in total_project_usages.items():
            if k in desired_fields:
                usage_dict[k] = v
        return usage_dict


def list_opts():
    yield batch_opt_group.name, batch_opts
