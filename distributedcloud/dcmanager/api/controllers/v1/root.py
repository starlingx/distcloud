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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#


from dcmanager.api.controllers.v1 import alarm_manager
from dcmanager.api.controllers.v1 import subclouds
from dcmanager.api.controllers.v1 import sw_update_options
from dcmanager.api.controllers.v1 import sw_update_strategy

import pecan


class Controller(object):

    def _get_resource_controller(self, remainder):

        if not remainder:
            pecan.abort(404)
            return
        minor_version = remainder[-1]
        remainder = remainder[:-1]
        sub_controllers = dict()
        if minor_version == '0':
            sub_controllers["subclouds"] = subclouds.SubcloudsController
            sub_controllers["alarms"] = alarm_manager.SubcloudAlarmController
            sub_controllers["sw-update-strategy"] = \
                sw_update_strategy.SwUpdateStrategyController
            sub_controllers["sw-update-options"] = \
                sw_update_options.SwUpdateOptionsController

        for name, ctrl in sub_controllers.items():
            setattr(self, name, ctrl)

        resource = remainder[0]
        if resource not in sub_controllers:
            pecan.abort(404)
            return

        remainder = remainder[1:]
        return sub_controllers[resource](), remainder

    @pecan.expose()
    def _lookup(self, *remainder):
        return self._get_resource_controller(remainder)
