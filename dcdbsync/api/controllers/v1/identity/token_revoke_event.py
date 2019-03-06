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

from oslo_config import cfg
from oslo_log import log as logging

import base64
import pecan
from pecan import expose
from pecan import request
from pecan import response

from dcdbsync.api.controllers import restcomm
from dcdbsync.common import exceptions
from dcdbsync.common.i18n import _
from dcdbsync.db.identity import api as db_api

import json

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class RevokeEventsController(object):
    VERSION_ALIASES = {
        'Pike': '1.0',
    }

    def __init__(self):
        super(RevokeEventsController, self).__init__()

    # to do the version compatibility for future purpose
    def _determine_version_cap(self, target):
        version_cap = 1.0
        return version_cap

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method='POST', template='json')
    def post(self):
        """Create a new token revoke event."""

        context = restcomm.extract_context_from_environ()

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(400, _('Request body decoding error'))

        if not payload:
            pecan.abort(400, _('Body required'))

        try:
            # Insert the token revoke event into DB tables
            revoke_event_ref = db_api.revoke_event_create(context, payload)
            response.status = 201
            return revoke_event_ref

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to create token revocation event'))

    @index.when(method='GET', template='json')
    def get(self):
        """Get all of token revoke events."""
        context = restcomm.extract_context_from_environ()

        try:
            return db_api.revoke_event_get_all(context)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to get token revocation events'))

    def _get_resource_controller(self, remainder):
        if not remainder:
            pecan.abort(404)
            return

        res_controllers = dict()
        res_controllers["audits"] = AuditsController
        res_controllers["users"] = UsersController

        for name, ctrl in res_controllers.items():
            setattr(self, name, ctrl)

        resource = remainder[0]
        if resource not in res_controllers:
            pecan.abort(404)
            return

        remainder = remainder[1:]
        return res_controllers[resource](), remainder

    @pecan.expose()
    def _lookup(self, *remainder):
        return self._get_resource_controller(remainder)


class UsersController(object):
    def __init__(self):
        super(UsersController, self).__init__()

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method='GET', template='json')
    def get(self, event_id=None):
        """Get a token revoke event by user_id and issued_before."""

        context = restcomm.extract_context_from_environ()

        if event_id is None:
            pecan.abort(400, _('Event ID required'))

        try:
            # user specific event id is in the format of
            # <user_id>_<issued_before> and encoded in base64
            event_ref = base64.urlsafe_b64decode(str(event_id))
            event_tags = event_ref.split('_')
            user_id = event_tags[0]
            issued_before = event_tags[1]

            revoke_event = db_api.\
                revoke_event_get_by_user(context, user_id=user_id,
                                         issued_before=issued_before)
            return revoke_event

        except (IndexError, TypeError):
            pecan.abort(404, _('Invalid event ID format'))
        except exceptions.RevokeEventNotFound:
            unique_id = "user_id {} and issued_before {}".\
                format(user_id, issued_before)
            pecan.abort(404, _("Token revocation event %s doesn't exist.")
                        % unique_id)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to get token revocation event'))

    @index.when(method='DELETE')
    def delete(self, event_id=None):
        """Delete a token revoke event by user_id and issued_before."""

        context = restcomm.extract_context_from_environ()

        if event_id is None:
            pecan.abort(400, _('Event ID required'))

        try:
            # user specific event id is in the format of
            # <user_id>_<issued_before> and encoded in base64
            event_ref = base64.urlsafe_b64decode(str(event_id))
            event_tags = event_ref.split('_')
            user_id = event_tags[0]
            issued_before = event_tags[1]
            db_api.revoke_event_delete_by_user(context, user_id=user_id,
                                               issued_before=issued_before)
            response.headers['Content-Type'] = None

        except (IndexError, TypeError):
            pecan.abort(404, _('Invalid event ID format'))
        except exceptions.RevokeEventNotFound:
            unique_id = "user_id {} and issued_before {}".\
                format(user_id, issued_before)
            pecan.abort(404, _("Token revocation event %s doesn't exist.")
                        % unique_id)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to delete token revocation event'))


class AuditsController(object):
    def __init__(self):
        super(AuditsController, self).__init__()

    @expose(generic=True, template='json')
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method='GET', template='json')
    def get(self, audit_id=None):
        """Get a token revoke event by revocation_event.audit_id."""

        context = restcomm.extract_context_from_environ()

        if audit_id is None:
            pecan.abort(400, _('Audit ID required'))

        try:
            revoke_event = db_api.\
                revoke_event_get_by_audit(context, audit_id=audit_id)
            return revoke_event

        except exceptions.RevokeEventNotFound:
            pecan.abort(404, _("Token revocation event with id %s"
                               " doesn't exist.") % audit_id)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to get token revocation event'))

    @index.when(method='DELETE')
    def delete(self, audit_id=None):
        """Delete a token revoke event by revocation_event.audit_id."""

        context = restcomm.extract_context_from_environ()

        if audit_id is None:
            pecan.abort(400, _('Audit ID required'))

        try:
            db_api.revoke_event_delete_by_audit(context, audit_id=audit_id)
            response.headers['Content-Type'] = None

        except exceptions.RevokeEventNotFound:
            pecan.abort(404, _("Token revocation event with id %s"
                               " doesn't exist.") % audit_id)

        except Exception as e:
            LOG.exception(e)
            pecan.abort(500, _('Unable to delete token revocation event'))
