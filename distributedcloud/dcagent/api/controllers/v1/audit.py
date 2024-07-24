#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import http.client
import json

from oslo_config import cfg
from oslo_log import log as logging
import pecan
from pecan import expose
from pecan import request

from dcagent.common.audit_manager import RequestedAudit
from dcagent.common.exceptions import UnsupportedAudit
from dcagent.common.i18n import _

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class AuditController(object):
    @expose(generic=True, template="json")
    def index(self):
        # Route the request to specific methods with parameters
        pass

    @index.when(method="PATCH", template="json")
    def patch(self):
        """Return the audit information."""

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(http.client.BAD_REQUEST, _("Request body decoding error"))

        if not payload:
            pecan.abort(http.client.BAD_REQUEST, _("Body required"))

        try:
            # Delete "use_cache" from payload so it doesn't get passed as an audit
            use_cache = payload.pop("use_cache", True)
            requested_audit = RequestedAudit(use_cache=use_cache)
            return requested_audit.get_sync_status(payload)

        except UnsupportedAudit as ex:
            LOG.exception(ex)
            pecan.abort(http.client.BAD_REQUEST, ex.msg)
        except Exception as ex:
            LOG.exception(ex)
            msg = f"Unable to get audit info: {ex}"
            pecan.abort(http.client.INTERNAL_SERVER_ERROR, _(msg))
