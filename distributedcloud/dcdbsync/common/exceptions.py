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
# Copyright (c) 2019-2021, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
DBsync agent base exception handling.
"""
import six

from oslo_utils import encodeutils
from oslo_utils import excutils

from dcdbsync.common.i18n import _


class DBsyncException(Exception):
    """Base DB sync agent Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(DBsyncException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(DBsyncException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return encodeutils.exception_to_unicode(self.msg)

    def use_fatal_exceptions(self):
        return False


class NotFound(DBsyncException):
    message = _("Not found")


class NotAuthorized(DBsyncException):
    message = _("Not authorized.")


class Forbidden(DBsyncException):
    message = _("Requested API is forbidden.")


class AdminRequired(NotAuthorized):
    message = _("User does not have admin privileges: %(reason)s")


class UserNotFound(NotFound):
    message = _("User with id %(user_id)s doesn't exist.")


class GroupNotFound(NotFound):
    message = _("Group with id %(group_id)s doesn't exist.")


class ProjectNotFound(NotFound):
    message = _("Project with id %(project_id)s doesn't exist.")


class RoleNotFound(NotFound):
    message = _("Role with id %(role_id)s doesn't exist.")


class ProjectRoleAssignmentNotFound(NotFound):
    message = _("Project role assignment with id"
                " %(project_role_assignment_id)s doesn't exist.")


class RevokeEventNotFound(NotFound):
    message = _("Token revocation event with id %(revoke_event_id)s"
                " doesn't exist.")
