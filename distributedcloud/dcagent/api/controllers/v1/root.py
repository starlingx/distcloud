#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan

from dcagent.api.controllers.v1 import audit


class Controller(object):
    def _get_resource_controller(self, remainder):

        if not remainder:
            pecan.abort(404)
            return

        remainder = remainder[:-1]

        res_controllers = dict()
        res_controllers["dcaudit"] = audit.AuditController

        for name, ctrl in res_controllers.items():
            setattr(self, name, ctrl)

        try:
            resource = remainder[0]
        except IndexError:
            pecan.abort(404)
            return

        if resource not in res_controllers:
            pecan.abort(404)
            return

        remainder = remainder[1:]
        return res_controllers[resource](), remainder

    @pecan.expose()
    def _lookup(self, *remainder):
        return self._get_resource_controller(remainder)
