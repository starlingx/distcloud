# Copyright (c) 2017 Ericsson AB.
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
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from dcdbsync.api.controllers.v1.identity import root

import pecan


class Controller(object):

    def _get_sub_controller(self, remainder):

        if not remainder:
            pecan.abort(404)
            return

        minor_version = remainder[-1]
        remainder = remainder[:-1]

        sub_controllers = dict()
        if minor_version == '0':
            sub_controllers["identity"] = root.IdentityController

        for name, ctrl in sub_controllers.items():
            setattr(self, name, ctrl)

        try:
            sub_controller = remainder[0]
        except IndexError:
            pecan.abort(404)
            return

        if sub_controller not in sub_controllers:
            pecan.abort(404)
            return

        remainder = remainder[1:]
        return sub_controllers[sub_controller](), remainder

    @pecan.expose()
    def _lookup(self, *remainder):
        return self._get_sub_controller(remainder)
