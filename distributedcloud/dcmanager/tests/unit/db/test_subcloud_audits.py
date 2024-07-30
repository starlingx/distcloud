# Copyright (c) 2021-2022, 2024 Wind River Systems, Inc.
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

import datetime

from oslo_db import exception as db_exception
from oslo_utils import uuidutils

from dcmanager.common import exceptions as exception
from dcmanager.db import api
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.tests import base

get_engine = api.get_engine


class DBAPISubcloudAuditsTest(base.DCManagerTestCase):
    @staticmethod
    def create_subcloud(ctxt, name, **kwargs):
        values = {
            "name": name,
            "description": "This is a subcloud",
            "location": "This is the location of the subcloud",
            "software_version": "10.04",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.2",
            "management_end_ip": "192.168.101.50",
            "systemcontroller_gateway_ip": "192.168.204.101",
            "deploy_status": "not-deployed",
            "error_description": "No errors present",
            "region_name": uuidutils.generate_uuid().replace("-", ""),
            "openstack_installed": False,
            "group_id": 1,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    def setUp(self):
        super(DBAPISubcloudAuditsTest, self).setUp()
        # calling setUp for the superclass sets up the DB and context

        self.create_subcloud(self.ctx, "subcloud1")
        self.create_subcloud(self.ctx, "subcloud2")
        self.create_subcloud(self.ctx, "subcloud3")

    def test_subcloud_audits_get(self):
        # Test the SubcloudAudits created when we created subcloud2 in setup.
        result = db_api.subcloud_audits_get(self.ctx, 2)
        self.assertEqual(result["subcloud_id"], 2)
        self.assertEqual(result["audit_started_at"], datetime.datetime(1, 1, 1, 0, 0))
        self.assertEqual(result["audit_finished_at"], datetime.datetime(1, 1, 1, 0, 0))
        self.assertEqual(result["patch_audit_requested"], False)
        self.assertEqual(result["load_audit_requested"], False)
        self.assertEqual(result["firmware_audit_requested"], False)
        self.assertEqual(result["kubernetes_audit_requested"], False)
        self.assertEqual(result["kube_rootca_update_audit_requested"], False)
        self.assertEqual(result["spare_audit_requested"], False)
        self.assertEqual(result["spare2_audit_requested"], False)
        self.assertEqual(result["reserved"], None)

    def test_subcloud_audits_get_not_found(self):
        self.assertRaises(
            exception.SubcloudNotFound, db_api.subcloud_audits_get, self.ctx, "4"
        )

    def test_subcloud_alarms_create_duplicate(self):
        # There's already an entry for subcloud2, try adding another.
        self.assertRaises(
            db_exception.DBDuplicateEntry, db_api.subcloud_audits_create, self.ctx, 2
        )

    def test_subcloud_audits_get_all(self):
        subcloud_audits = db_api.subcloud_audits_get_all(self.ctx)
        self.assertEqual(len(subcloud_audits), 3)
        self.assertEqual(subcloud_audits[0]["subcloud_id"], 1)
        self.assertEqual(subcloud_audits[1]["subcloud_id"], 2)
        self.assertEqual(subcloud_audits[2]["subcloud_id"], 3)

    def test_subcloud_alarms_delete(self):
        result = db_api.subcloud_audits_get(self.ctx, 2)
        db_api.subcloud_destroy(self.ctx, result["subcloud_id"])
        self.assertRaises(
            exception.SubcloudNotFound,
            db_api.subcloud_audits_get,
            self.ctx,
            result["subcloud_id"],
        )

    def test_subcloud_audits_update(self):
        result = db_api.subcloud_audits_get(self.ctx, 1)
        self.assertEqual(result["patch_audit_requested"], False)
        result = db_api.subcloud_audits_get(self.ctx, 2)
        self.assertEqual(result["patch_audit_requested"], False)
        values = {"patch_audit_requested": True}
        result = db_api.subcloud_audits_update(self.ctx, 2, values)
        self.assertEqual(result["patch_audit_requested"], True)
        result = db_api.subcloud_audits_get(self.ctx, 1)
        self.assertEqual(result["patch_audit_requested"], False)
        result = db_api.subcloud_audits_get(self.ctx, 2)
        self.assertEqual(result["patch_audit_requested"], True)

    def test_subcloud_audits_update_all(self):
        subcloud_audits = db_api.subcloud_audits_get_all(self.ctx)
        for audit in subcloud_audits:
            self.assertEqual(audit["patch_audit_requested"], False)
            self.assertEqual(audit["load_audit_requested"], False)
        values = {"patch_audit_requested": True, "load_audit_requested": True}
        result = db_api.subcloud_audits_update_all(self.ctx, values)
        self.assertEqual(result, 3)
        subcloud_audits = db_api.subcloud_audits_get_all(self.ctx)
        for audit in subcloud_audits:
            self.assertEqual(audit["patch_audit_requested"], True)
            self.assertEqual(audit["load_audit_requested"], True)

    def test_subcloud_audits_get_all_need_audit(self):
        current_time = datetime.datetime.utcnow()
        last_audit_threshold = current_time - datetime.timedelta(seconds=1000)
        audits = db_api.subcloud_audits_get_all_need_audit(
            self.ctx, last_audit_threshold
        )
        # They should all need audits.
        self.assertEqual(len(audits), 3)
        # Update subcloud1 to show it's been audited recently and
        # check it doesn't come back as needing an audit.
        db_api.subcloud_audits_end_audit(self.ctx, 1, [])
        audits = db_api.subcloud_audits_get_all_need_audit(
            self.ctx, last_audit_threshold
        )
        subcloud_ids = [audit[0].subcloud_id for audit in audits]
        self.assertEqual(len(subcloud_ids), 2)
        self.assertNotIn(1, subcloud_ids)
        # Set one of the special audits to make sure it overrides.
        values = {"patch_audit_requested": True}
        db_api.subcloud_audits_update(self.ctx, 1, values)
        audits = db_api.subcloud_audits_get_all_need_audit(
            self.ctx, last_audit_threshold
        )
        self.assertEqual(len(audits), 3)

    def test_subcloud_audits_start_and_end(self):
        audit = db_api.subcloud_audits_get_and_start_audit(self.ctx, 3)
        self.assertTrue(
            (datetime.datetime.utcnow() - audit.audit_started_at)
            < datetime.timedelta(seconds=1)
        )
        audit = db_api.subcloud_audits_end_audit(self.ctx, 3, [])
        self.assertTrue(
            (datetime.datetime.utcnow() - audit.audit_finished_at)
            < datetime.timedelta(seconds=1)
        )
        self.assertFalse(audit.state_update_requested)

    def test_subcloud_audits_fix_expired(self):
        # Set the 'finished' timestamp later than the 'start' timestamp.
        db_api.subcloud_audits_end_audit(self.ctx, 3, [])
        # Set the 'start' timestamp later than the 'finished' timestamp
        # but with the 'finished' timestamp long ago.
        db_api.subcloud_audits_get_and_start_audit(self.ctx, 1)
        # Set the 'start' timestamp later than the 'finished' timestamp
        # but with the 'finished' timestamp recent.
        db_api.subcloud_audits_end_audit(self.ctx, 2, [])
        db_api.subcloud_audits_get_and_start_audit(self.ctx, 2)
        last_audit_threshold = datetime.datetime.utcnow() - datetime.timedelta(
            seconds=100
        )
        count = db_api.subcloud_audits_fix_expired_audits(
            self.ctx, last_audit_threshold
        )
        self.assertEqual(count, 1)
        # Check that for the one that was updated we didn't trigger sub-audits.
        result = db_api.subcloud_audits_get(self.ctx, 1)
        self.assertEqual(result["patch_audit_requested"], False)

    def test_subcloud_audits_fix_expired_trigger_audits(self):
        # Set the 'start' timestamp later than the 'finished' timestamp
        # but with the 'finished' timestamp long ago.
        db_api.subcloud_audits_get_and_start_audit(self.ctx, 1)
        last_audit_threshold = datetime.datetime.utcnow() - datetime.timedelta(
            seconds=100
        )
        # Fix up expired audits and trigger subaudits.
        count = db_api.subcloud_audits_fix_expired_audits(
            self.ctx, last_audit_threshold, trigger_audits=True
        )
        self.assertEqual(count, 1)
        # For the fixed-up audits, subaudits should be requested.
        result = db_api.subcloud_audits_get(self.ctx, 1)
        self.assertEqual(result["patch_audit_requested"], True)
        self.assertEqual(result["firmware_audit_requested"], True)
        self.assertEqual(result["load_audit_requested"], True)
        self.assertEqual(result["kubernetes_audit_requested"], True)
        self.assertEqual(result["kube_rootca_update_audit_requested"], True)
        # For the not-fixed-up audits, subaudits should not be requested.
        result = db_api.subcloud_audits_get(self.ctx, 2)
        self.assertEqual(result["patch_audit_requested"], False)
        self.assertEqual(result["firmware_audit_requested"], False)
        self.assertEqual(result["load_audit_requested"], False)
        self.assertEqual(result["kubernetes_audit_requested"], False)
        self.assertEqual(result["kube_rootca_update_audit_requested"], False)

    def test_subcloud_audits_bulk_end_audit(self):
        db_api.subcloud_audits_bulk_end_audit(self.ctx, [1, 2])
        subcloud_audits1 = db_api.subcloud_audits_get(self.ctx, 1)
        subcloud_audits2 = db_api.subcloud_audits_get(self.ctx, 2)
        subcloud_audits3 = db_api.subcloud_audits_get(self.ctx, 3)
        self.assertEqual(
            subcloud_audits1["audit_finished_at"], subcloud_audits2["audit_finished_at"]
        )
        self.assertTrue(
            subcloud_audits1["audit_finished_at"]
            > subcloud_audits3["audit_finished_at"]
        )
