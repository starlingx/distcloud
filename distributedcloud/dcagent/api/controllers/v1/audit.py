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

from dcagent.api.controllers import restcomm
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

        context = restcomm.extract_context_from_environ()

        # Convert JSON string in request to Python dict
        try:
            payload = json.loads(request.body)
        except ValueError:
            pecan.abort(http.client.BAD_REQUEST, _("Request body decoding error"))

        if not payload:
            pecan.abort(http.client.BAD_REQUEST, _("Body required"))

        # TODO(vgluzrom): Remove extra_args from header and keep it only in payload
        # once all supported dcagent versions have this possibility. If system
        # controller sends extra_args in payload to a dcagent that doesn't support it,
        # it will raise an UnsupportedAudit exception.
        try:
            headers = json.loads(request.headers.get("X-DCAGENT-HEADERS", "{}"))
        except ValueError:
            pecan.abort(http.client.BAD_REQUEST, _("Request headers decoding error"))

        extra_args = payload.pop("extra_args", {})
        extra_args = {**extra_args, **headers}

        LOG.debug(
            f"Payload sent by system controller: {payload}. Extra args: {extra_args}"
        )

        try:
            # Delete "use_cache" from payload so it doesn't get passed as an audit
            use_cache = payload.pop("use_cache", True)
            # request_token is used for calls not involving cache
            requested_audit = RequestedAudit(
                request_token=context.auth_token, use_cache=use_cache
            )
            return requested_audit.get_sync_status(payload, extra_args)

        except UnsupportedAudit as ex:
            LOG.exception(ex)
            pecan.abort(http.client.BAD_REQUEST, ex.msg)
        except Exception as ex:
            LOG.exception(ex)
            msg = f"Unable to get audit info: {ex}"
            pecan.abort(http.client.INTERNAL_SERVER_ERROR, _(msg))
