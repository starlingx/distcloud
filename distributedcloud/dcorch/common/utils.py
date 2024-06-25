# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2018-2022, 2024 Wind River Systems, Inc.
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

import itertools
import uuid

from oslo_db import exception as oslo_db_exception
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.objects import orchjob
from dcorch.objects import resource
from dcorch.objects import subcloud as subcloud_obj

LOG = logging.getLogger(__name__)


def get_import_path(cls):
    return cls.__module__ + "." + cls.__name__


# Returns a iterator of tuples containing batch_size number of objects in each
def get_batch_projects(batch_size, project_list, fillvalue=None):
    args = [iter(project_list)] * batch_size
    return itertools.zip_longest(fillvalue=fillvalue, *args)


# to do validate the quota limits
def validate_quota_limits(payload):
    for rsrc in payload:
        # Check valid resource name
        if rsrc not in itertools.chain(dccommon_consts.CINDER_QUOTA_FIELDS,
                                       dccommon_consts.NOVA_QUOTA_FIELDS,
                                       dccommon_consts.NEUTRON_QUOTA_FIELDS):
            raise exceptions.InvalidInputError
        # Check valid quota limit value in case for put/post
        if isinstance(payload, dict) and (not isinstance(
                payload[rsrc], int) or payload[rsrc] <= 0):
            raise exceptions.InvalidInputError


def keypair_construct_id(name, user_id):
    # Keypair has a unique name per user.
    # Hence, keypair id stored in dcorch DB is of the format
    # "<name>/<user_id>".
    return name + consts.KEYPAIR_ID_DELIM + user_id


def keypair_constructed_id(id):
    if id and id.find(consts.KEYPAIR_ID_DELIM) > 0:
        return True
    return False


def keypair_deconstruct_id(id):
    if keypair_constructed_id(id):
        return id.split(consts.KEYPAIR_ID_DELIM)
    else:
        return [id, ""]


def enqueue_work(context, endpoint_type,
                 resource_type, source_resource_id,
                 operation_type, resource_info=None,
                 subcloud=None):
    """Enqueue work into the DB

    :param context:  authorization context
    :param endpoint_type: consts.ENDPOINT_TYPE_*
    :param resource_type: consts.RESOURCE_TYPE_*
    :param source_resource_id: resource id in system controller
    :param operation_type: consts.OPERATION_TYPE_*
    :param resource_info: json string representing resource info, optional
    :param subcloud: subcloud resource, optional
    :return: nothing

    The enqueue_work() routine would be used by the API proxy code, to store
    information about a requested sync job in the DB.  It would typically be
    followed by a call to sync_request() to wake up the sync threads in case
    they're sleeping.

    It would be called like this to create and then delete a flavor:

        utils.enqueue_work(context,
                           consts.ENDPOINT_TYPE_COMPUTE,
                           consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
                           '0bbdb1ed-acc9-440f-b6e9-b1c6d37d9a56',
                           consts.OPERATION_TYPE_CREATE,
                           resource_info='{"ram": 512, "vcpus": 3,
                                           "name": "testflavor",
                                           "disk":10, "id":"auto"}')

        utils.enqueue_work(context,
                           consts.ENDPOINT_TYPE_COMPUTE,
                           consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
                           '0bbdb1ed-acc9-440f-b6e9-b1c6d37d9a56',
                           consts.OPERATION_TYPE_DELETE)

    Flavor-access add/remove examples:

        utils.enqueue_work(context.get_admin_context(),
                           consts.ENDPOINT_TYPE_COMPUTE,
                           consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
                           '0bbdb1ed-acc9-440f-b6e9-b1c6d37d9a56',
                           consts.OPERATION_TYPE_ACTION,
                           resource_info='{
                             "addTenantAccess": {"tenant": "new_tenant"}}')

        utils.enqueue_work(context.get_admin_context(),
                           consts.ENDPOINT_TYPE_COMPUTE,
                           consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
                           '0bbdb1ed-acc9-440f-b6e9-b1c6d37d9a56',
                           consts.OPERATION_TYPE_ACTION,
                           resource_info='{
                             "removeTenantAccess": {"tenant": "new_tenant"}}')

    """
    if operation_type in [consts.OPERATION_TYPE_CREATE,
                          consts.OPERATION_TYPE_PATCH]:
        try:
            rsrc = resource.Resource(
                context=context, resource_type=resource_type,
                master_id=source_resource_id)
            rsrc.create()
            LOG.info("Resource created in DB {}/{}/{}/{}".format(
                # pylint: disable-next=no-member
                rsrc.id,
                resource_type, source_resource_id, operation_type))
        except oslo_db_exception.DBDuplicateEntry:
            # In case of discrepancies found during audit, resource might
            # be already present in DB, but not its dependent resources.
            # A retry of create should work, in such cases.
            # Another scenario handled here is that of two threads trying to
            # create the resource at the same time. One will fail due to unique
            # constraint uniq_resource0resource_type0master_id0deleted
            rsrc = resource.Resource.get_by_type_and_master_id(
                context, resource_type, source_resource_id)
            LOG.info("Resource already in DB {}/{}/{}/{}".format(
                # pylint: disable-next=no-member
                rsrc.id, resource_type, source_resource_id, operation_type))
        except Exception as e:
            LOG.exception(e)
            return
    else:
        try:
            rsrc = resource.Resource.get_by_type_and_master_id(
                context, resource_type, source_resource_id)
        except exceptions.ResourceNotFound:
            # Some resources do not go through a create
            LOG.info("Resource not in DB {}/{}/{}".format(
                resource_type, source_resource_id, operation_type))
            rsrc = resource.Resource(
                context=context, resource_type=resource_type,
                master_id=source_resource_id)
            rsrc.create()

    # todo: user_id and project_id are not used, to be removed from model
    orch_job = orchjob.OrchJob(
        context=context, user_id='', project_id='',
        endpoint_type=endpoint_type, source_resource_id=source_resource_id,
        # pylint: disable-next=no-member
        operation_type=operation_type, resource_id=rsrc.id,
        resource_info=resource_info)
    orch_job.create()
    if subcloud:
        subclouds = [subcloud]
    else:
        subclouds = subcloud_obj.SubcloudList.get_all(context)

    orch_requests = []
    for sc in subclouds:
        # Create a dictionary for each orchestration request with a unique UUID,
        # state = 'queued', the target region name, and the orch_job ID
        orch_request = {
            'uuid': str(uuid.uuid4()),
            'state': consts.ORCH_REQUEST_QUEUED,
            'target_region_name': sc.region_name,
            # pylint: disable-next=no-member
            'orch_job_id': orch_job.id,
        }
        orch_requests.append(orch_request)

    # Use the bulk_insert_mappings method to insert all orchestration requests
    # in a single session
    db_api.orch_request_create_bulk(context, orch_requests)
    LOG.info(
        f"Work order created for {len(subclouds)} subclouds for resource "
        # pylint: disable-next=no-member
        f"{rsrc.id}/{resource_type}/{source_resource_id}/{operation_type}"
    )
