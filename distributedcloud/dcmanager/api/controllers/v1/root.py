# Copyright (c) 2017 Ericsson AB.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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
import pecan

from dcmanager.api.controllers.v1 import alarm_manager
from dcmanager.api.controllers.v1 import notifications
from dcmanager.api.controllers.v1 import phased_subcloud_deploy
from dcmanager.api.controllers.v1 import subcloud_backup
from dcmanager.api.controllers.v1 import subcloud_deploy
from dcmanager.api.controllers.v1 import subcloud_group
from dcmanager.api.controllers.v1 import subclouds
from dcmanager.api.controllers.v1 import sw_update_options
from dcmanager.api.controllers.v1 import sw_update_strategy
from dcmanager.api.controllers.v1 import system_peers


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
            sub_controllers["subcloud-deploy"] = subcloud_deploy.\
                SubcloudDeployController
            sub_controllers["alarms"] = alarm_manager.SubcloudAlarmController
            sub_controllers["sw-update-strategy"] = \
                sw_update_strategy.SwUpdateStrategyController
            sub_controllers["sw-update-options"] = \
                sw_update_options.SwUpdateOptionsController
            sub_controllers["subcloud-groups"] = \
                subcloud_group.SubcloudGroupsController
            sub_controllers["notifications"] = \
                notifications.NotificationsController
            sub_controllers["subcloud-backup"] = subcloud_backup.\
                SubcloudBackupController
            sub_controllers["phased-subcloud-deploy"] = phased_subcloud_deploy.\
                PhasedSubcloudDeployController
            sub_controllers["system-peers"] = system_peers.\
                SystemPeersController

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
