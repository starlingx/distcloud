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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

"""
DC Manager base exception handling.
"""
import six

from oslo_utils import encodeutils
from oslo_utils import excutils

from dcmanager.common.i18n import _


class DCManagerException(Exception):
    """Base DC Manager Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(DCManagerException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(DCManagerException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return encodeutils.exception_to_unicode(self.msg)

    def use_fatal_exceptions(self):
        return False


class BadRequest(DCManagerException):
    message = _('Bad %(resource)s request: %(msg)s')


class ValidateFail(DCManagerException):
    def __init__(self, message):
        self.message = message
        super(ValidateFail, self).__init__()


class NotFound(DCManagerException):
    message = _("Not found")


class Conflict(DCManagerException):
    message = _('Conflict: %(msg)s')


class NotAuthorized(DCManagerException):
    message = _("Not authorized.")


class ServiceUnavailable(DCManagerException):
    message = _("The service is unavailable")


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges: %(reason)s")


class InUse(DCManagerException):
    message = _("The resource is inuse")


class InvalidConfigurationOption(DCManagerException):
    message = _("An invalid value was provided for %(opt_name)s: "
                "%(opt_value)s")


class InvalidParameterValue(DCManagerException):
    message = _("%(err)s")


class SubcloudAlreadyExists(Conflict):
    message = _("Subcloud with region_name=%(region_name)s already exists")


class SubcloudNotFound(NotFound):
    message = _("Subcloud with id %(subcloud_id)s doesn't exist.")


class SubcloudNameNotFound(NotFound):
    message = _("Subcloud with name %(name)s doesn't exist.")


class SubcloudNotOnline(DCManagerException):
    message = _("Subcloud is not online.")


class SubcloudStatusNotFound(NotFound):
    message = _("SubcloudStatus with subcloud_id %(subcloud_id)s and "
                "endpoint_type %(endpoint_type)s doesn't exist.")


class SubcloudNotUnmanaged(DCManagerException):
    message = _("Subcloud must be unmanaged to perform this operation.")


class SubcloudNotOffline(DCManagerException):
    message = _("Subcloud must be powered down to perform this operation.")


class SubcloudPatchOptsNotFound(NotFound):
    message = _("No options found for Subcloud with id %(subcloud_id)s, "
                "defaults will be used.")


class SubcloudGroupNotFound(NotFound):
    message = _("Subcloud Group with id %(group_id)s doesn't exist.")


class SubcloudGroupNameNotFound(NotFound):
    message = _("Subcloud Group with name %(name)s doesn't exist.")


class SubcloudGroupNameViolation(DCManagerException):
    message = _("Default Subcloud Group name cannot be changed or reused.")


class SubcloudGroupDefaultNotDeletable(DCManagerException):
    message = _("Default Subcloud Group %(group_id)s may not be deleted.")


class ConnectionRefused(DCManagerException):
    message = _("Connection to the service endpoint is refused")


class TimeOut(DCManagerException):
    message = _("Timeout when connecting to OpenStack Service")


class InternalError(DCManagerException):
    message = _("Error when performing operation")


class InvalidInputError(DCManagerException):
    message = _("An invalid value was provided")


class LicenseInstallError(DCManagerException):
    message = _("Error while installing license on subcloud: %(subcloud_id)s")


class LicenseMissingError(DCManagerException):
    message = _("License does not exist on subcloud: %(subcloud_id)s")


class VaultLoadMissingError(DCManagerException):
    message = _("No matching: %(file_type) found in vault: %(vault_dir)")


class StrategyStepNotFound(NotFound):
    message = _("StrategyStep with subcloud_id %(subcloud_id)s "
                "doesn't exist.")


class StrategyStepNameNotFound(NotFound):
    message = _("StrategyStep with name %(name)s doesn't exist.")
