#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Dcagent base exception handling.
"""

from oslo_utils import excutils

from dcdbsync.common.i18n import _


class DcagentException(Exception):
    """Base dcagent Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """

    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(DcagentException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(DcagentException, self).__init__(self.message)

    def use_fatal_exceptions(self):
        return False


class UnsupportedAudit(DcagentException):
    message = _("Requested audit %(audit)s is not supported.")
