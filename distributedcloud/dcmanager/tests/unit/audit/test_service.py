# Copyright (c) 2020-2021, 2024 Wind River Systems, Inc.
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

from oslo_config import cfg

from dcmanager.audit import service
from dcmanager.common import scheduler
from dcmanager.tests import base
from dcmanager.tests import utils

CONF = cfg.CONF


class TestDCManagerAuditService(base.DCManagerTestCase):

    def setUp(self):
        super(TestDCManagerAuditService, self).setUp()
        self.tenant_id = "fake_admin"
        self.thm = scheduler.ThreadGroupManager()
        self.context = utils.dummy_context(user="test_user", tenant=self.tenant_id)
        self.service_obj = service.DCManagerAuditService()

    def test_init(self):
        self.assertEqual(self.service_obj.host, "localhost")
        self.assertEqual(self.service_obj.topic, "dcmanager-audit")

    def test_init_tgm(self):
        self.service_obj.init_tgm()
        self.assertIsNotNone(self.service_obj.TG)
