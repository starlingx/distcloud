# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright 2015 Ericsson AB.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2020 Wind River Systems, Inc.
#

"""
DC Orchestrator base exception handling.
"""
import six

from oslo_utils import encodeutils
from oslo_utils import excutils

from dcorch.common.i18n import _


class OrchestratorException(Exception):
    """Base Orchestrator Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(OrchestratorException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(OrchestratorException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return encodeutils.exception_to_unicode(self.msg)

    def use_fatal_exceptions(self):
        return False


class BadRequest(OrchestratorException):
    message = _('Bad %(resource)s request: %(msg)s')


class NotFound(OrchestratorException):
    pass


class Conflict(OrchestratorException):
    pass


class NotAuthorized(OrchestratorException):
    message = _("Not authorized.")


class Forbidden(OrchestratorException):
    message = _("Requested API is forbidden")


class ServiceUnavailable(OrchestratorException):
    message = _("The service is unavailable")


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges: %(reason)s")


class InUse(OrchestratorException):
    message = _("The resource is inuse")


class InvalidConfigurationOption(OrchestratorException):
    message = _("An invalid value was provided for %(opt_name)s: "
                "%(opt_value)s")


class Invalid(OrchestratorException):
    message = _("Unacceptable parameters.")


class ProjectNotFound(NotFound):
    message = _("Project %(project_id)s doesn't exist.")


class ProjectQuotaNotFound(NotFound):
    message = _("Quota for project %(project_id)s doesn't exist.")


class QuotaClassNotFound(NotFound):
    message = _("Quota class %(class_name)s doesn't exist.")


class JobNotFound(NotFound):
    message = _("Job doesn't exist.")


class DependentImageNotFound(NotFound):
    message = _("Dependent image doesn't exist.")


class ImageFormatNotSupported(OrchestratorException):
    message = _("An invalid version was provided")


class ConnectionRefused(OrchestratorException):
    message = _("Connection to the service endpoint is refused")


class TimeOut(OrchestratorException):
    message = _("Timeout when connecting to OpenStack Service")


class InternalError(OrchestratorException):
    message = _("Error when performing operation")


class InvalidInputError(OrchestratorException):
    message = _("An invalid value was provided")


# Cannot be templated as the error syntax varies.
# msg needs to be constructed when raised.
class InvalidParameterValue(Invalid):
    message = _("%(err)s")


class SubcloudSyncAlreadyExists(Conflict):
    message = _("SubcloudSync subcloud: %(subcloud_name)s "
                "endpoint_type: %(endpoint_type)s already exists")


class SubcloudAlreadyExists(Conflict):
    message = _("Subcloud with region_name=%(region_name)s already exists")


class SubcloudResourceAlreadyExists(Conflict):
    message = _("Subcloud resource with subcloud_id=%(subcloud_id)s "
                "resource_id=%(resource_id)s already exists")


class SubcloudResourceNotFound(NotFound):
    message = _("SubcloudResource %(resource)s not available")


class EndpointNotReachable(OrchestratorException):
    message = _("The specified resource endpoint is not reachable")


class EndpointNotSupported(OrchestratorException):
    message = _("The specified resource endpoint %(endpoint)s is not"
                " supported")


class SyncRequestFailed(OrchestratorException):
    message = _("The sync operation failed")


class SyncRequestAbortedBySystem(OrchestratorException):
    message = _("The sync operation was aborted by the system because"
                " some condition was not met")


class SyncRequestFailedRetry(OrchestratorException):
    message = _("The sync operation failed, will retry")


class SyncRequestTimeout(OrchestratorException):
    message = _("The sync operation timed out")


class ResourceNotFound(NotFound):
    message = _("Resource not available")


class SubcloudNotFound(NotFound):
    message = _("Subcloud %(region_name)s not found")


class SubcloudSyncNotFound(NotFound):
    message = _("SubcloudSync subcloud: %(subcloud_name)s "
                "endpoint_type: %(endpoint_type)s not found")


class ThreadNotFound(NotFound):
    message = _("Thread %(thread_name)s of %(region_name)s not found")


class OrchJobNotFound(NotFound):
    message = _("OrchJob  %(orch_job)s not found")


class OrchJobAlreadyExists(Conflict):
    message = _("OrchJob with resource_id=%(resource_id)s "
                "endpoint_type=%(endpoint_type)s "
                "operation_type=%(operation_type)s already exists")


class OrchRequestNotFound(NotFound):
    message = _("OrchRequest  %(orch_request)s not found")


class OrchRequestAlreadyExists(Conflict):
    message = _("OrchRequest with orch_request=%(orch_request)s "
                "target_region_name=%(target_region_name)s already exists")


class ObjectActionError(OrchestratorException):
    msg_fmt = _('Object action %(action)s failed because: %(reason)s')


class CertificateExpiredException(OrchestratorException):
    message = _("Certificate is expired and will not be synced")
