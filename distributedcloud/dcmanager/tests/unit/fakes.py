# Copyright (c) 2017-2021, 2024 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import uuid

import mock
from oslo_utils import timeutils

# VIM constants for Strategy
APPLY_TYPE_SERIAL = "serial"
INSTANCE_ACTION_STOP_START = "stop-start"
ALARM_RESTRICTIONS_STRICT = "strict"


class FakeVimClient(object):
    def __init__(self):
        pass


class FakeVimStrategy(object):
    """Represents a VIM Strategy object defined in:

    starlingx/nfv/nfv-client/nfv_client/openstack/sw_update.py
    """

    def __init__(
        self,
        name="VIM Strategy",
        controller_apply_type=APPLY_TYPE_SERIAL,
        storage_apply_type=APPLY_TYPE_SERIAL,
        swift_apply_type=APPLY_TYPE_SERIAL,
        worker_apply_type=APPLY_TYPE_SERIAL,
        max_parallel_worker_hosts=2,
        default_instance_action=INSTANCE_ACTION_STOP_START,
        alarm_restrictions=ALARM_RESTRICTIONS_STRICT,
        current_phase=None,
        current_phase_completion_percentage=0,
        state=None,
        build_phase=None,
        apply_phase=None,
        abort_phase=None,
    ):
        self.uuid = str(uuid.uuid4())
        self.name = name
        self.controller_apply_type = controller_apply_type
        self.storage_apply_type = storage_apply_type
        self.swift_apply_type = swift_apply_type
        self.worker_apply_type = worker_apply_type
        self.max_parallel_worker_hosts = max_parallel_worker_hosts
        self.default_instance_action = default_instance_action
        self.alarm_restrictions = alarm_restrictions
        self.current_phase = current_phase
        self.current_phase_completion_percentage = current_phase_completion_percentage
        self.state = state
        self.build_phase = build_phase
        self.apply_phase = apply_phase
        self.abort_phase = abort_phase


class FakeVimStrategyPhase(object):
    """Represents a VIM StrategyPhase object defined in:

    starlingx/nfv/nfv-client/nfv_client/openstack/sw_update.py
    """

    def __init__(self, response=None, reason=None):
        self.response = response
        self.reason = reason


class SwUpdateStrategy(object):
    def __init__(self, id, data):
        self.id = id
        self.type = data["type"]
        self.subcloud_apply_type = data["subcloud-apply-type"]
        self.max_parallel_subclouds = int(data["max-parallel-subclouds"])
        if data["stop-on-failure"] == "true":
            self.stop_on_failure = True
        else:
            self.stop_on_failure = False
        self.state = data["state"]
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class FakeService(object):
    def __init__(self, name, type):
        self.name = name
        self.type = type


class FakeServices(object):
    def __init__(self, services=None):
        self.services = services

    def list(self):
        return self.services


class FakeKeystone(object):
    def __init__(self):
        self.session = mock.MagicMock()
        self.tokens = mock.MagicMock()
        self.keystone_client = FakeKeystoneClient()


class FakeKeystoneClient(object):
    def __init__(self):
        self.services = FakeServices()
