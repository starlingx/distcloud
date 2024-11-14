# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
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
import eventlet
import threading

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import sdk_platform as sdk
from dccommon.endpoint_cache import EndpointCache
from dccommon.utils import build_subcloud_endpoint
from dcdbsync.dbsyncclient import client as dbsyncclient
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common import utils
from dcorch.db import api as db_api
from dcorch.engine.fernet_key_manager import FERNET_REPO_MASTER_ID
from dcorch.objects import orchrequest
from dcorch.objects import resource
from dcorch.objects.subcloud import Subcloud
from dcorch.objects import subcloud_resource


from keystoneclient import client as keystoneclient


# Some of the variables defined in this file cannot be recognized by the
# current pylint check, thus will raise error which will fail tox check
# The pylint check is temporarily skipped on this file
# pylint: skip-file
LOG = logging.getLogger(__name__)

SYNC_TIMEOUT = 600  # Timeout for subcloud sync

# sync request states, should be in SyncRequest class
STATE_QUEUED = "queued"
STATE_IN_PROGRESS = "in-progress"
STATE_TIMEDOUT = "timedout"
STATE_ABORTED = "aborted"
STATE_FAILED = "failed"
STATE_COMPLETED = "completed"

# Audit findings
AUDIT_RESOURCE_MISSING = "missing"
AUDIT_RESOURCE_EXTRA = "extra_resource"

AUDIT_LOCK_NAME = "dcorch-audit"


def get_master_os_client(region_clients=None):
    # Used by the master clients only. The subcloud clients don't need to be
    # cached in the openstack driver, because we don't want to hold the admin
    # sessions for the subclouds.
    try:
        os_client = sdk.OpenStackDriver(
            region_name=dccommon_consts.CLOUD_0, region_clients=region_clients
        )
    except Exception as e:
        LOG.error(
            "Failed to get os_client for "
            f"{dccommon_consts.CLOUD_0}/{region_clients}: {e}."
        )
        raise e
    return os_client


class SyncThread(object):
    """Manages tasks related to resource management."""

    MAX_RETRY = 3
    PENDING_SYNC_REQUEST_STATES = (
        consts.ORCH_REQUEST_QUEUED,
        consts.ORCH_REQUEST_IN_PROGRESS,
        consts.ORCH_REQUEST_FAILED,
    )

    # used by the audit to cache the master resources
    master_resources_dict = collections.defaultdict(dict)

    def __init__(
        self,
        subcloud_name,
        endpoint_type=None,
        management_ip=None,
        software_version=None,
        subcloud_id=None,
        engine_id=None,
    ):
        self.endpoint_type = endpoint_type  # endpoint type
        self.subcloud_name = subcloud_name  # subcloud name
        self.management_ip = management_ip
        self.software_version = software_version
        self.subcloud_id = subcloud_id
        self.engine_id = engine_id
        self.ctxt = context.get_admin_context()
        self.sync_handler_map = {}
        self.master_region_name = dccommon_consts.CLOUD_0
        self.audit_resources = []

        self.log_extra = {"instance": self.subcloud_name + ": "}
        self.dcmanager_state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        self.dcmanager_rpc_client = dcmanager_rpc_client.ManagerClient()

        self.sc_admin_session = None
        self.sc_auth_url = None
        self.admin_session = None
        self.ks_client = None
        self.dbs_client = None

    def should_exit(self):
        # Return whether the sync/audit threads should exit.
        try:
            db_api.subcloud_sync_get(self.ctxt, self.subcloud_name, self.endpoint_type)
        except exceptions.SubcloudSyncNotFound:
            return True

        return False

    def is_subcloud_managed(self):
        # is this subcloud managed
        subcloud = Subcloud.get_by_name(self.ctxt, self.subcloud_name)
        return subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED

    def is_subcloud_enabled(self):
        # is this subcloud enabled
        subcloud = Subcloud.get_by_name(self.ctxt, self.subcloud_name)

        # We only enable syncing if the subcloud is online and the initial
        # sync has completed.
        if subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE and (
            subcloud.initial_sync_state == consts.INITIAL_SYNC_STATE_COMPLETED
        ):
            return True
        else:
            return False

    def initialize(self):
        # base implementation of initializing the master client.
        # The specific SyncThread subclasses may extend this.

        if self.endpoint_type in dccommon_consts.ENDPOINT_TYPES_LIST:
            config = cfg.CONF.endpoint_cache
            self.admin_session = EndpointCache.get_admin_session(
                config.auth_uri,
                config.username,
                config.user_domain_name,
                config.password,
                config.project_name,
                config.project_domain_name,
                timeout=60,
            )
        elif self.endpoint_type in dccommon_consts.ENDPOINT_TYPES_LIST_OS:
            config = cfg.CONF.openstack_cache
            self.admin_session = EndpointCache.get_admin_session(
                config.auth_uri,
                config.admin_username,
                config.admin_user_domain_name,
                config.admin_password,
                config.admin_tenant,
                config.admin_project_domain_name,
                timeout=60,
            )
        else:
            raise exceptions.EndpointNotSupported(endpoint=self.endpoint_type)

        # keystone client
        self.ks_client = keystoneclient.Client(
            session=self.admin_session, region_name=dccommon_consts.CLOUD_0
        )
        # dcdbsync client
        self.dbs_client = dbsyncclient.Client(
            endpoint_type=consts.DBS_ENDPOINT_INTERNAL,
            session=self.admin_session,
            region_name=dccommon_consts.CLOUD_0,
        )

    def initialize_sc_clients(self):
        # base implementation of initializing the subcloud specific
        # clients, only used by the subclasses.
        # The specific SyncThread subclasses may extend this
        if not self.sc_admin_session:
            # Subclouds will use token from the Subcloud specific Keystone,
            # so define a session against that subcloud's keystone endpoint
            self.sc_auth_url = build_subcloud_endpoint(self.management_ip, "keystone")
            LOG.debug(
                f"Built sc_auth_url {self.sc_auth_url} for subcloud "
                f"{self.subcloud_name}"
            )

            if self.endpoint_type in dccommon_consts.ENDPOINT_TYPES_LIST:
                config = cfg.CONF.endpoint_cache
                self.sc_admin_session = EndpointCache.get_admin_session(
                    self.sc_auth_url,
                    config.username,
                    config.user_domain_name,
                    config.password,
                    config.project_name,
                    config.project_domain_name,
                    timeout=60,
                )
            elif self.endpoint_type in dccommon_consts.ENDPOINT_TYPES_LIST_OS:
                config = cfg.CONF.openstack_cache
                self.sc_admin_session = EndpointCache.get_admin_session(
                    self.sc_auth_url,
                    config.admin_username,
                    config.admin_user_domain_name,
                    config.admin_password,
                    config.admin_tenant,
                    config.admin_project_domain_name,
                    timeout=60,
                )

    def initial_sync(self):
        # Return True to indicate initial sync success
        return True

    def enable(self):
        # Called when DC manager thinks this subcloud is good to go.
        self.run_sync_audit()

    def get_db_subcloud_resource(self, rsrc_id):
        try:
            if self.subcloud_id is None:
                self.subcloud_id = Subcloud.get_by_name(
                    self.ctxt, self.subcloud_name
                ).id
            subcloud_rsrc = (
                subcloud_resource.SubcloudResource.get_by_resource_and_subcloud(
                    self.ctxt, rsrc_id, self.subcloud_id
                )
            )  # pylint: disable=E1101
            return subcloud_rsrc
        except exceptions.SubcloudResourceNotFound:
            LOG.info(
                "{} not found in subcloud {} resource table".format(
                    rsrc_id, self.subcloud_id
                ),
                extra=self.log_extra,
            )
        return None

    def persist_db_subcloud_resource(self, db_rsrc_id, subcloud_rsrc_id):
        # This function can be invoked after creating a subcloud resource.
        # Persist the subcloud resource to the DB for later
        #
        # Parameters:
        #   db_rsrc_id: the "id" field of the resource in the DB
        #   subcloud_rsrc_id: the unique identifier of the subcloud resource

        subcloud_rsrc = self.get_db_subcloud_resource(db_rsrc_id)
        if not subcloud_rsrc:
            if self.subcloud_id is None:
                self.subcloud_id = Subcloud.get_by_name(
                    self.ctxt, self.subcloud_name
                ).id
            subcloud_rsrc = subcloud_resource.SubcloudResource(
                self.ctxt,
                subcloud_resource_id=subcloud_rsrc_id,
                resource_id=db_rsrc_id,
                subcloud_id=self.subcloud_id,
            )  # pylint: disable=E1101
            # There is no race condition for creation of
            # subcloud_resource as it is always done from the same thread.
            subcloud_rsrc.create()
        elif subcloud_rsrc.subcloud_resource_id != subcloud_rsrc_id:
            # May be the resource was manually deleted from the subcloud.
            # So, update the dcorch DB with the new resource id from subcloud.
            subcloud_rsrc.subcloud_resource_id = subcloud_rsrc_id
            LOG.info(
                "Updating {}:{} [{}]".format(
                    db_rsrc_id, subcloud_rsrc.subcloud_resource_id, subcloud_rsrc_id
                ),
                extra=self.log_extra,
            )
            subcloud_rsrc.save()
        else:
            LOG.info(
                "subcloud_rsrc {}:{} [{}] is up-to-date".format(
                    db_rsrc_id, subcloud_rsrc.subcloud_resource_id, subcloud_rsrc_id
                ),
                extra=self.log_extra,
            )
        return subcloud_rsrc.subcloud_resource_id

    def sync_resource(self, sync_request):
        rsrc = resource.Resource.get_by_id(self.ctxt, sync_request.orch_job.resource_id)
        # pylint: disable=E1101
        handler = self.sync_handler_map[rsrc.resource_type]
        LOG.info(
            "{} Invoking {} for {} [{}]".format(
                self.engine_id,
                handler.__name__,
                rsrc.resource_type,
                sync_request.orch_job.operation_type,
            ),
            extra=self.log_extra,
        )
        handler(sync_request, rsrc)

    def set_sync_status(self, sync_status, alarmable=True):
        # Only report sync_status when managed
        subcloud_managed = self.is_subcloud_managed()
        if not subcloud_managed:
            LOG.debug(
                "set_sync_status: skip update sync update for unmanaged "
                "subcloud {}".format(self.subcloud_name)
            )
            return

        subcloud_sync = db_api.subcloud_sync_get(
            self.ctxt, self.subcloud_name, self.endpoint_type
        )

        if subcloud_sync.sync_status_report_time:
            delta = timeutils.delta_seconds(
                subcloud_sync.sync_status_report_time, timeutils.utcnow()
            )
            if delta < 3600:
                if subcloud_sync.sync_status_reported == sync_status:
                    LOG.debug(
                        "skip set_sync_status sync_status_reported={}, "
                        "sync_status={}".format(
                            subcloud_sync.sync_status_reported, sync_status
                        ),
                        extra=self.log_extra,
                    )
                    return

        LOG.info(
            "{}: set_sync_status {}, alarmable: {}".format(
                self.subcloud_name, sync_status, alarmable
            ),
            extra=self.log_extra,
        )

        self.dcmanager_state_rpc_client.update_subcloud_endpoint_status(
            self.ctxt,
            subcloud_region=self.subcloud_name,
            endpoint_type=self.endpoint_type,
            sync_status=sync_status,
            alarmable=alarmable,
        )

        db_api.subcloud_sync_update(
            self.ctxt,
            self.subcloud_name,
            self.endpoint_type,
            values={
                "sync_status_reported": sync_status,
                "sync_status_report_time": timeutils.utcnow(),
            },
        )

    def sync(self):
        LOG.debug(
            "{}: starting sync routine".format(self.subcloud_name), extra=self.log_extra
        )
        region_name = self.subcloud_name

        sync_requests = orchrequest.OrchRequestList.get_by_attrs(
            self.ctxt,
            self.endpoint_type,
            target_region_name=region_name,
            states=self.PENDING_SYNC_REQUEST_STATES,
        )

        # Early exit in case there are no pending sync requests
        if not sync_requests:
            LOG.debug(
                "Sync resources done for subcloud - no sync requests",
                extra=self.log_extra,
            )
            self.set_sync_status(dccommon_consts.SYNC_STATUS_IN_SYNC)
            return

        LOG.info(
            "Got {} sync request(s)".format(len(sync_requests)),
            extra=self.log_extra,
        )

        actual_sync_requests = []
        for req in sync_requests:
            # Failed orch requests were taken into consideration when reporting
            # sync status to the dcmanager. They need to be removed from the
            # orch requests list before proceeding.
            if req.state != consts.ORCH_REQUEST_STATE_FAILED:
                actual_sync_requests.append(req)

        if not actual_sync_requests:
            LOG.info(
                "Sync resources done for subcloud - no valid sync requests",
                extra=self.log_extra,
            )
            # We got FAILED requests, set sync_status=out-of-sync
            self.set_sync_status(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
            return
        elif not self.is_subcloud_enabled():
            LOG.info(
                "Sync resources done for subcloud - subcloud is disabled",
                extra=self.log_extra,
            )
            self.set_sync_status(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
            return

        # Subcloud is enabled and there are pending sync requests, so
        # we have work to do.
        request_aborted = False
        timeout = eventlet.timeout.Timeout(SYNC_TIMEOUT)
        try:
            for request in actual_sync_requests:
                if not self.is_subcloud_enabled() or self.should_exit():
                    # Oops, someone disabled the endpoint while
                    # we were processing work for it.
                    raise exceptions.EndpointNotReachable()
                request.state = consts.ORCH_REQUEST_STATE_IN_PROGRESS
                try:
                    request.save()  # save to DB
                except exceptions.OrchRequestNotFound:
                    # This case is handled in loop below, but should also be
                    # handled here as well.
                    LOG.info(
                        "Orch request already deleted request uuid=%s state=%s"
                        % (request.uuid, request.state),
                        extra=self.log_extra,
                    )
                    continue

                retry_count = 0
                while retry_count < self.MAX_RETRY:
                    try:
                        self.sync_resource(request)
                        # Sync succeeded, mark the request as
                        # completed for tracking/debugging purpose
                        # and tag it for purge when its deleted
                        # time exceeds the data retention period.
                        request.state = consts.ORCH_REQUEST_STATE_COMPLETED
                        request.deleted = 1
                        request.deleted_at = timeutils.utcnow()
                        request.save()
                        break
                    except exceptions.OrchRequestNotFound:
                        LOG.info(
                            "Orch request already deleted request uuid=%s state=%s"
                            % (request.uuid, request.state),
                            extra=self.log_extra,
                        )
                        break
                    except exceptions.SyncRequestTimeout:
                        request.try_count += 1
                        request.save()
                        retry_count += 1
                        if retry_count >= self.MAX_RETRY:
                            raise exceptions.EndpointNotReachable()
                    except exceptions.SyncRequestFailedRetry:
                        LOG.info(
                            "SyncRequestFailedRetry for {}/{}".format(
                                self.subcloud_name, self.endpoint_type
                            ),
                            extra=self.log_extra,
                        )
                        request.try_count += 1
                        request.state = consts.ORCH_REQUEST_STATE_FAILED
                        request.save()
                        retry_count += 1

                        # Incremental backoff retry is implemented to define the wait
                        # time between each attempt to retry the sync.
                        #   1st retry: 1s.
                        #   2nd retry: 3s.
                        if retry_count < self.MAX_RETRY:
                            # Only sleep if this is not the last retry
                            sleep_duration = 1 + (retry_count - 1) * 2
                            eventlet.greenthread.sleep(sleep_duration)
                        else:
                            LOG.error(
                                "SyncRequestFailedRetry: max retries reached "
                                "for {}/{}".format(
                                    self.subcloud_name, self.endpoint_type
                                ),
                                extra=self.log_extra,
                            )
                    except exceptions.SyncRequestFailed:
                        LOG.error(
                            "SyncRequestFailed for {}/{}".format(
                                self.subcloud_name, self.endpoint_type
                            ),
                            extra=self.log_extra,
                        )
                        request.state = consts.ORCH_REQUEST_STATE_FAILED
                        request.save()
                        retry_count = self.MAX_RETRY
                        request_aborted = True
                    except exceptions.SyncRequestAbortedBySystem:
                        request.state = consts.ORCH_REQUEST_STATE_FAILED
                        request.save()
                        retry_count = self.MAX_RETRY
                        request_aborted = True
                    except Exception as e:
                        LOG.error(
                            f"Unexpected error during sync: {e}",
                            extra=self.log_extra,
                        )
                        request.state = consts.ORCH_REQUEST_STATE_FAILED
                        request.save()
                        retry_count = self.MAX_RETRY

                # If we fall out of the retry loop we either succeeded
                # or failed multiple times and want to move to the next
                # request.

        except eventlet.timeout.Timeout:
            # The entire sync operation timed out, covering all sync requests.
            # Just log the exception and continue to check if there are
            # pending requests.
            LOG.exception(
                f"Sync timed out for {self.subcloud_name}/{self.endpoint_type}."
            )

        except exceptions.EndpointNotReachable:
            # Endpoint not reachable, throw away all the sync requests.
            LOG.info(
                "EndpointNotReachable, {} sync requests pending".format(
                    len(actual_sync_requests)
                ),
                extra=self.log_extra,
            )
            # del sync_requests[:] #This fails due to:
            # 'OrchRequestList' object does not support item deletion

        finally:
            timeout.cancel()

        sync_requests = orchrequest.OrchRequestList.get_by_attrs(
            self.ctxt,
            self.endpoint_type,
            target_region_name=region_name,
            states=self.PENDING_SYNC_REQUEST_STATES,
        )

        alarmable = False
        for req in sync_requests:
            # Any failed state should be alarmable
            if req.state == consts.ORCH_REQUEST_STATE_FAILED:
                alarmable = True

            # Do not raise an alarm if all the sync requests are due to
            # a fernet key rotation, as these are expected to occur
            # periodically.
            if req.orch_job.source_resource_id != FERNET_REPO_MASTER_ID:
                alarmable = True

        # If there are pending requests, update the status to out-of-sync.
        if sync_requests:
            # If the request was aborted due to an expired certificate,
            # update the status to 'out-of-sync' and just return so the
            # sync_request is updated to "completed". This way, the sync
            # job won't attempt to retry the sync in the next cycle.
            if request_aborted:
                self.set_sync_status(dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
                LOG.info(
                    "End of resource sync out-of-sync. {} sync request(s): "
                    "request_aborted".format(len(sync_requests)),
                    extra=self.log_extra,
                )
                return
            # Otherwise, e.g. timeout or EndpointNotReachable,
            # update the status and raise an exception to set the sync_request to
            # 'failed', so the sync job will re-attempt the sync in the next
            # sync cycle.
            else:
                self.set_sync_status(
                    dccommon_consts.SYNC_STATUS_OUT_OF_SYNC, alarmable=alarmable
                )
                LOG.info(
                    "End of resource sync out-of-sync. {} sync request(s)".format(
                        len(sync_requests)
                    ),
                    extra=self.log_extra,
                )
                msg = (
                    f"There are {len(sync_requests)} pending requests to sync. "
                    "Will retry in next sync cycle."
                )
                raise Exception(msg)

        else:
            self.set_sync_status(dccommon_consts.SYNC_STATUS_IN_SYNC)
            LOG.info(
                "End of resource sync in-sync. {} sync request(s)".format(
                    len(sync_requests)
                ),
                extra=self.log_extra,
            )

        LOG.info(
            "Sync resources done for subcloud - "
            "synced {} request(s)".format(len(actual_sync_requests)),
            extra=self.log_extra,
        )

    def run_sync_audit(self, engine_id=None):
        if self.endpoint_type in cfg.CONF.disable_audit_endpoints:
            LOG.warn("Audit disabled!", extra=self.log_extra)
            return
        LOG.debug(
            "Engine id={}: sync_audit started".format(engine_id), extra=self.log_extra
        )
        try:
            self.sync_audit(engine_id)
        finally:
            self.post_audit()

    def sync_audit(self, engine_id):
        LOG.debug(
            "Engine id={}: starting sync audit".format(engine_id), extra=self.log_extra
        )

        most_recent_failed_request = (
            orchrequest.OrchRequest.get_most_recent_failed_request(self.ctxt)
        )

        if most_recent_failed_request:
            LOG.debug(
                "Most recent failed request id=%s, timestamp=%s",
                most_recent_failed_request.id,
                most_recent_failed_request.updated_at,
            )
        else:
            LOG.debug("There are no failed requests.")

        total_num_of_audit_jobs = 0

        # TODO(ecandotti): move this behavior to SysinvSyncThread class

        # If the endpoint is of type Platform and the subcloud has dcagent,
        # retrieve all platform resources with a single dcagent call to avoid
        # making separate get_dcagent_resources calls for each resource type.
        if self.endpoint_type == dccommon_consts.ENDPOINT_TYPE_PLATFORM and (
            self.has_dcagent
        ):
            all_master_resources = dict()
            for resource_type in self.audit_resources:
                all_master_resources[resource_type] = self.get_cached_master_resources(
                    resource_type
                )
            platform_resources = self.get_dcagent_resources(
                self.audit_resources, all_master_resources
            )
            if platform_resources is None:
                # If subcloud is not reachable, abort audit.
                return

        for resource_type in self.audit_resources:
            if not self.is_subcloud_enabled() or self.should_exit():
                LOG.info(
                    "{}: aborting sync audit, as subcloud is disabled".format(
                        threading.currentThread().getName()
                    ),
                    extra=self.log_extra,
                )
                return

            # Skip resources with outstanding sync requests
            region_name = self.subcloud_name
            sync_requests = []
            states = [
                consts.ORCH_REQUEST_QUEUED,
                consts.ORCH_REQUEST_IN_PROGRESS,
            ]
            sync_requests = orchrequest.OrchRequestList.get_by_attrs(
                self.ctxt,
                self.endpoint_type,
                resource_type=resource_type,
                target_region_name=region_name,
                states=states,
            )
            abort_resources = [req.orch_job.source_resource_id for req in sync_requests]
            if len(sync_requests) > 0:
                LOG.info(
                    "Will not audit {}. {} sync request(s) pending".format(
                        abort_resources, len(sync_requests)
                    ),
                    extra=self.log_extra,
                )

            num_of_audit_jobs = 0
            try:
                m_resources, db_resources, sc_resources = self.get_all_resources(
                    resource_type
                )

                if self.endpoint_type == dccommon_consts.ENDPOINT_TYPE_PLATFORM and (
                    self.has_dcagent
                ):
                    sc_resources = platform_resources[resource_type]

                # todo: delete entries in db_resources with no corresponding
                # entry in m_resources?

                if sc_resources is None or m_resources is None:
                    return
                LOG.debug("Audit {}".format(resource_type), extra=self.log_extra)
                LOG.debug(
                    "Auditing {}: master={} db={} sc={}".format(
                        resource_type, m_resources, db_resources, sc_resources
                    ),
                    extra=self.log_extra,
                )
                num_of_audit_jobs += self.audit_find_missing(
                    resource_type,
                    m_resources,
                    db_resources,
                    sc_resources,
                    abort_resources,
                )
                num_of_audit_jobs += self.audit_find_extra(
                    resource_type,
                    m_resources,
                    db_resources,
                    sc_resources,
                    abort_resources,
                )
            except Exception:
                LOG.exception("Unexpected error while auditing %s", resource_type)

            # Extra resources in subcloud are not impacted by the audit.

            if not num_of_audit_jobs:
                LOG.debug(
                    "Clean audit run for {}".format(resource_type), extra=self.log_extra
                )
            else:
                LOG.info(
                    "{} num_of_audit_jobs for {}".format(
                        num_of_audit_jobs, resource_type
                    ),
                    extra=self.log_extra,
                )

            total_num_of_audit_jobs += num_of_audit_jobs

        if most_recent_failed_request:
            # Soft delete all failed requests in the previous sync audit.
            try:
                orchrequest.OrchRequest.delete_previous_failed_requests(
                    self.ctxt, most_recent_failed_request.updated_at
                )
            except Exception:
                # shouldn't get here
                LOG.exception("Unexpected error!")

        if not total_num_of_audit_jobs:
            # todo: if we had an "unable to sync this
            # subcloud/endpoint" alarm raised, then clear it
            pass

        db_api.subcloud_sync_update(
            self.ctxt,
            self.subcloud_name,
            self.endpoint_type,
            values={"sync_request": consts.SYNC_STATUS_REQUESTED},
        )
        LOG.debug(
            "{}: done sync audit".format(threading.currentThread().getName()),
            extra=self.log_extra,
        )

    def post_audit(self):
        # Some specific SyncThread subclasses may perform post audit actions
        utils.close_session(
            self.sc_admin_session, "audit", f"{self.subcloud_name}/{self.endpoint_type}"
        )

    @classmethod
    @lockutils.synchronized(AUDIT_LOCK_NAME)
    def reset_master_resources_cache(cls):
        # reset the cached master resources
        LOG.debug("Reset the cached master resources.")
        SyncThread.master_resources_dict = collections.defaultdict(dict)

    def audit_find_missing(
        self, resource_type, m_resources, db_resources, sc_resources, abort_resources
    ):
        """Find missing resources in subcloud.

        - Input param db_resources is modified in this routine
          to remove entries that match the resources in
          master cloud. At the end, db_resources will have a
          list of resources that are present in dcorch DB, but
          not present in the master cloud.
        """
        num_of_audit_jobs = 0
        for m_r in m_resources:
            master_id = self.get_resource_id(resource_type, m_r)
            if master_id in abort_resources:
                LOG.info(
                    "audit_find_missing: Aborting audit for {}".format(master_id),
                    extra=self.log_extra,
                )
                num_of_audit_jobs += 1
                # There are pending jobs for this resource, abort audit
                continue

            missing_resource = False
            m_rsrc_db = None
            for db_resource in db_resources:
                if db_resource.master_id == master_id:
                    m_rsrc_db = db_resource
                    db_resources.remove(db_resource)
                    break

            if m_rsrc_db:
                # resource from master cloud is present in DB.

                # Contents of "m_r" may refer to other master cloud resources.
                # Make a copy with the references updated to refer to subcloud
                # resources.
                try:
                    m_r_updated = self.update_resource_refs(resource_type, m_r)
                except exceptions.SubcloudResourceNotFound:
                    # If we couldn't find the equivalent subcloud resources,
                    # we don't know what to look for in the subcloud so skip
                    # this m_r and go to the next one.
                    continue

                # Now, look for subcloud resource in DB.
                # If present: look for actual resource in the
                # subcloud and compare the resource details.
                # If not present: create resource in subcloud.
                db_sc_resource = self.get_db_subcloud_resource(m_rsrc_db.id)
                if db_sc_resource:
                    if not db_sc_resource.is_managed():
                        LOG.info(
                            "Resource {} is not managed".format(master_id),
                            extra=self.log_extra,
                        )
                        continue
                    sc_rsrc_present = False
                    # The subcloud resource will only have "in-sync" or "out-of-sync"
                    # if returned by dcagent. For platform resources, audit_dependants
                    # will always return 0.
                    if self.is_dcagent_managed_resource(resource_type):
                        sc_rsrc_present = self.is_resource_present_in_subcloud(
                            resource_type, master_id, sc_resources
                        )
                    else:
                        for sc_r in sc_resources:
                            sc_id = self.get_resource_id(resource_type, sc_r)
                            if sc_id == db_sc_resource.subcloud_resource_id:
                                if self.same_resource(resource_type, m_r_updated, sc_r):
                                    LOG.debug(
                                        "Resource type {} {} is in-sync".format(
                                            resource_type, master_id
                                        ),
                                        extra=self.log_extra,
                                    )
                                    num_of_audit_jobs += self.audit_dependants(
                                        resource_type, m_r, sc_r
                                    )
                                    sc_rsrc_present = True
                                    break
                    if not sc_rsrc_present:
                        LOG.info(
                            "Subcloud resource {} found in master cloud & DB, "
                            "but the exact same resource not found in subcloud".format(
                                db_sc_resource.subcloud_resource_id
                            ),
                            extra=self.log_extra,
                        )
                        # Subcloud resource is present in DB, but the check
                        # for same_resource() was negative. Either the resource
                        # disappeared from subcloud or the resource details
                        # are different from that of master cloud. Let the
                        # resource implementation decide on the audit action.
                        missing_resource = self.audit_discrepancy(
                            resource_type, m_r, sc_resources
                        )
                else:
                    LOG.info(
                        "Subcloud res {} not found in DB, will create".format(
                            master_id
                        ),
                        extra=self.log_extra,
                    )
                    # Check and see if there are any subcloud resources that
                    # match the master resource, and if so set up mappings.
                    # This returns true if it finds a match.
                    if self.map_subcloud_resource(
                        resource_type, m_r_updated, m_rsrc_db, sc_resources
                    ):
                        continue
                    missing_resource = True

            else:  # master_resource not in resource DB
                LOG.info(
                    "{} not found in DB, will create it".format(master_id),
                    extra=self.log_extra,
                )
                # Check and see if there are any subcloud resources that
                # match the master resource, and if so set up mappings.
                # This returns true if it finds a match.
                # This is for the case where the resource is not even in dcorch
                # resource DB (ie, resource has not been tracked by dcorch yet)
                if self.map_subcloud_resource(
                    resource_type, m_r, m_rsrc_db, sc_resources
                ):
                    continue
                missing_resource = True

            if missing_resource:
                # Resource is missing from subcloud, take action
                num_of_audit_jobs += self.audit_action(
                    resource_type, AUDIT_RESOURCE_MISSING, m_r
                )

                # As the subcloud resource is missing, invoke
                # the hook for dependants with no subcloud resource.
                # Resource implementation should handle this.
                num_of_audit_jobs += self.audit_dependants(resource_type, m_r, None)
        if num_of_audit_jobs != 0:
            LOG.info(
                "audit_find_missing {} num_of_audit_jobs".format(num_of_audit_jobs),
                extra=self.log_extra,
            )
        return num_of_audit_jobs

    def audit_find_extra(
        self, resource_type, m_resources, db_resources, sc_resources, abort_resources
    ):
        """Find extra resources in subcloud.

        - Input param db_resources is expected to be a
          list of resources that are present in dcorch DB, but
          not present in the master cloud.
        """

        num_of_audit_jobs = 0
        # At this point, db_resources contains resources present in DB,
        # but not in master cloud
        for db_resource in db_resources:
            if db_resource.master_id:
                if db_resource.master_id in abort_resources:
                    LOG.info(
                        "audit_find_extra: Aborting audit for {}".format(
                            db_resource.master_id
                        ),
                        extra=self.log_extra,
                    )
                    num_of_audit_jobs += 1
                    # There are pending jobs for this resource, abort audit
                    continue

                LOG.debug(
                    "Extra resource ({}) in DB".format(db_resource.id),
                    extra=self.log_extra,
                )
                subcloud_rsrc = self.get_db_subcloud_resource(db_resource.id)
                if subcloud_rsrc:
                    if not subcloud_rsrc.is_managed():
                        LOG.info(
                            "Resource {} is not managed".format(
                                subcloud_rsrc.subcloud_resource_id
                            ),
                            extra=self.log_extra,
                        )
                        continue

                    # check if the resource exists in subcloud, no need to
                    # schedule work if it doesn't exist in subcloud.
                    # This is a precautionary action in case the resource
                    # has already be deleted in the subcloud which can happen
                    # for example, user deletes the resource from master right
                    # after an audit (not through api-proxy), then user deletes
                    # that resource manually in the subcloud before the
                    # next audit.
                    if not self.resource_exists_in_subcloud(
                        subcloud_rsrc, sc_resources
                    ):
                        continue

                    LOG.info(
                        "Resource ({}) and subcloud resource ({}) "
                        "not in sync with master cloud".format(
                            db_resource.master_id, subcloud_rsrc.subcloud_resource_id
                        ),
                        extra=self.log_extra,
                    )
                    # There is extra resource in the subcloud, take action.
                    # Note that the resource is in dcorch DB, but not
                    # actually present in the master cloud.
                    num_of_audit_jobs += self.audit_action(
                        resource_type, AUDIT_RESOURCE_EXTRA, db_resource
                    )
                else:
                    # Resource is present in resource table, but not in
                    # subcloud_resource table. We have also established that
                    # the corresponding OpenStack resource is not present in
                    # the master cloud.
                    # There might be another subcloud with "unmanaged"
                    # subcloud resource corresponding to this resource.
                    # So, just ignore this here!
                    pass

        return num_of_audit_jobs

    def schedule_work(
        self,
        endpoint_type,
        resource_type,
        source_resource_id,
        operation_type,
        resource_info=None,
    ):
        LOG.info(
            "Scheduling {} work for {}/{}".format(
                operation_type, resource_type, source_resource_id
            ),
            extra=self.log_extra,
        )
        try:
            subcloud = Subcloud.get_by_name(self.ctxt, self.subcloud_name)
            utils.enqueue_work(
                self.ctxt,
                endpoint_type,
                resource_type,
                source_resource_id,
                operation_type,
                resource_info,
                subcloud=subcloud,
            )
        except Exception as e:
            LOG.info(
                "Exception in schedule_work: {}".format(str(e)), extra=self.log_extra
            )

    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, "master_id"):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id
        else:
            # Else, return id field (by default)
            return resource.id

    # Audit functions to be overridden in inherited classes
    def get_all_resources(self, resource_type):
        m_resources = None
        db_resources = None
        sc_resources = None
        # Get resources from dcdbsync if the endpoint is not platform or it is
        # but the subcloud doesn't support dcagent. In case it has dcagent,
        # the subcloud resources have already been retrieved for all platform
        # resources previously
        if self.endpoint_type != dccommon_consts.ENDPOINT_TYPE_PLATFORM or not (
            self.has_dcagent
        ):
            sc_resources = self.get_subcloud_resources(resource_type)
            # If subcloud is not reachable, abort audit.
            if sc_resources is None:
                return m_resources, db_resources, sc_resources
        db_resources = self.get_db_master_resources(resource_type)
        m_resources = self.get_cached_master_resources(resource_type)
        return m_resources, db_resources, sc_resources

    @lockutils.synchronized(AUDIT_LOCK_NAME)
    def get_cached_master_resources(self, resource_type):
        if resource_type in SyncThread.master_resources_dict:
            m_resources = SyncThread.master_resources_dict[resource_type]
        else:
            m_resources = self.get_master_resources(resource_type)
            if m_resources is not None:
                SyncThread.master_resources_dict[resource_type] = m_resources
        return m_resources

    def get_subcloud_resources(self, resource_type):
        return None

    def get_db_master_resources(self, resource_type):
        return list(resource.ResourceList.get_all(self.ctxt, resource_type))

    def get_master_resources(self, resource_type):
        return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        return True

    def has_same_ids(self, resource_type, m_resource, sc_resource):
        return False

    def is_dcagent_managed_resource(self, resource_type):
        return False

    def is_resource_present_in_subcloud(self, resource_type, master_id, sc_resources):
        return False

    def map_subcloud_resource(self, resource_type, m_r, m_rsrc_db, sc_resources):
        # Child classes can override this function to map an existing subcloud
        # resource to an existing master resource.  If a mapping is created
        # the function should return True.
        #
        # It is expected that update_resource_refs() has been called on m_r.
        return False

    def update_resource_refs(self, resource_type, m_r):
        # Child classes can override this function to update any references
        # to other master resources embedded within the info of this resource.
        return m_r

    def audit_dependants(self, resource_type, m_resource, sc_resource):
        num_of_audit_jobs = 0
        if not self.is_subcloud_enabled() or self.should_exit():
            return num_of_audit_jobs
        if not sc_resource:
            # Handle None value for sc_resource
            pass
        return num_of_audit_jobs

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # Return true to try creating the resource again
        return True

    def audit_action(self, resource_type, finding, resource):
        LOG.info(
            "audit_action: {}/{}".format(finding, resource_type), extra=self.log_extra
        )
        # Default actions are create & delete. Can be overridden
        # in resource implementation
        num_of_audit_jobs = 0
        # resource can be either from dcorch DB or fetched by OpenStack query
        resource_id = self.get_resource_id(resource_type, resource)
        if finding == AUDIT_RESOURCE_MISSING:
            # default action is create for a 'missing' resource
            self.schedule_work(
                self.endpoint_type,
                resource_type,
                resource_id,
                consts.OPERATION_TYPE_CREATE,
                self.get_resource_info(
                    resource_type, resource, consts.OPERATION_TYPE_CREATE
                ),
            )
            num_of_audit_jobs += 1
        elif finding == AUDIT_RESOURCE_EXTRA:
            # default action is delete for an 'extra_resource'
            # resource passed in is db_resource (resource in dcorch DB)
            self.schedule_work(
                self.endpoint_type,
                resource_type,
                resource_id,
                consts.OPERATION_TYPE_DELETE,
            )
            num_of_audit_jobs += 1
        return num_of_audit_jobs

    def get_resource_info(self, resource_type, resource, operation_type=None):
        return ""

    # check if the subcloud resource (from dcorch subcloud_resource table)
    # exists in subcloud resources.
    def resource_exists_in_subcloud(self, subcloud_rsrc, sc_resources):
        return True
