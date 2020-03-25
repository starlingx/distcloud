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


class DCCommonException(Exception):
    """Base Commond Driver Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(DCCommonException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(DCCommonException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return encodeutils.exception_to_unicode(self.msg)

    def use_fatal_exceptions(self):
        return False


class NotFound(DCCommonException):
    pass


class Conflict(DCCommonException):
    pass


class ServiceUnavailable(DCCommonException):
    message = _("The service is unavailable")


class InvalidInputError(DCCommonException):
    message = _("An invalid value was provided")


class InternalError(DCCommonException):
    message = _("Error when performing operation")


class OAMAddressesNotFound(NotFound):
    message = _("OAM Addresses Not Found")


class TrapDestAlreadyExists(Conflict):
    message = _("TrapDest in region=%(region_name)s ip_address=%(ip_address)s "
                "community=%(community)s already exists")


class TrapDestNotFound(NotFound):
    message = _("Trapdest in region=%(region_name)s with ip_address "
                "%(ip_address)s not found")


class CommunityAlreadyExists(Conflict):
    message = _("Community %(community)s in region=%(region_name)s "
                "already exists")


class CommunityNotFound(NotFound):
    message = _("Community %(community)s not found in region=%(region_name)s")


class CertificateNotFound(NotFound):
    message = _("Certificate in region=%(region_name)s with signature "
                "%(signature)s not found")