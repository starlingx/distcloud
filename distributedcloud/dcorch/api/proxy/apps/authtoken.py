#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import threading

from keystonemiddleware import auth_token
from oslo_log import log as logging
from platform_util.oidc import oidc_utils
import webob.dec
from webob import Response

from dcorch.api.proxy.common.service import Middleware
from dcorch.common import exceptions
from dcorch.common.i18n import _


LOG = logging.getLogger(__name__)


class AuthWrapper(Middleware):
    """Authentication wrapper that supports both Keystone and OIDC."""

    def __init__(self, app, conf=None):
        self.app = app
        self.conf = conf or {}

        # Initialize Keystone auth middleware
        self.keystone_auth = auth_token.AuthProtocol(app, conf)

        # Initialize OIDC token cache and defaults
        self._oidc_token_cache = {}
        self._oidc_cache_lock = threading.Lock()
        self.default_domain = conf.get("oidc_default_domain", "Default")
        self.default_project = conf.get("oidc_default_project", "admin")

    @webob.dec.wsgify
    def __call__(self, req):
        """Route authentication based on token type."""

        # Check for Keystone token first
        keystone_token = req.headers.get("X-Auth-Token")
        if keystone_token:
            LOG.info("Using Keystone authentication")
            return self.keystone_auth

        # Check for OIDC token
        oidc_token = req.headers.get("OIDC-Token")

        if oidc_token:
            LOG.info("Using OIDC authentication")
            return self._handle_oidc_auth(req, oidc_token)

        # No authentication token found
        LOG.warning("No authentication token found in request")
        return self._auth_error_response("Missing authentication token")

    def _handle_oidc_auth(self, req, oidc_token):
        """Handle OIDC authentication logic."""
        try:
            claims = self._oidc_auth(oidc_token)
            self._inject_oidc_claims(req.environ, claims)
            return req.get_response(self.app)

        except exceptions.NotAuthorized as e:
            LOG.error("OIDC authentication failed: %s", str(e))
            return self._auth_error_response(f"OIDC authentication failed: {str(e)}")

    def _auth_error_response(self, message):
        """Return standardized authentication error response."""
        error = {
            "faultcode": "Client",
            "faultstring": message,
            "debuginfo": None,
        }
        response_body = json.dumps({"error_message": json.dumps(error)})
        body = response_body.encode("utf-8")

        return Response(
            body=body, status=401, content_type="application/json", charset="utf-8"
        )

    def _inject_oidc_claims(self, environ, claims):
        """Inject OIDC claims into request environment."""

        # Populate the environment variables in a way that is consistent
        # with Keystone, ensuring they can be used for authorization
        environ["HTTP_X_ROLE"] = ",".join(claims.get("roles", []))
        environ["HTTP_X_ROLES"] = environ["HTTP_X_ROLE"]
        environ["HTTP_X_USER_NAME"] = claims.get("username", "")
        environ["HTTP_X_PROJECT_NAME"] = self.default_project

    def _oidc_auth(self, oidc_token):
        """Perform OIDC authentication and return claims."""
        if not oidc_token:
            msg = _("Missing OIDC token in the request")
            LOG.error(msg)
            raise exceptions.NotAuthorized(message=msg)

        try:
            with self._oidc_cache_lock:
                oidc_claims = oidc_utils.get_oidc_token_claims(
                    oidc_token, self._oidc_token_cache
                )
            return oidc_utils.parse_oidc_token_claims(
                oidc_claims, self.default_domain, self.default_project
            )
        except Exception as e:
            msg = _("OIDC token validation failed: %s") % e
            LOG.error(msg)
            raise exceptions.NotAuthorized(message=msg)
