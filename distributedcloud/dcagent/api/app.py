#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan

from keystonemiddleware import auth_token
from oslo_config import cfg
from oslo_middleware import request_id
from oslo_service import service

from dcagent.common import context as ctx
from dcagent.common.i18n import _


def setup_app(*args, **kwargs):

    opts = cfg.CONF.pecan
    config = {
        "server": {"port": cfg.CONF.bind_port, "host": cfg.CONF.bind_host},
        "app": {
            "root": "dcagent.api.controllers.root.RootController",
            "modules": ["dcagent.api"],
            "debug": opts.debug,
            "auth_enable": opts.auth_enable,
            "errors": {400: "/error", "__force_dict__": True},
        },
    }

    pecan_config = pecan.configuration.conf_from_dict(config)

    app = pecan.make_app(
        pecan_config.app.root,
        debug=False,
        wrap_app=_wrap_app,
        force_canonical=False,
        hooks=lambda: [ctx.AuthHook()],
        guess_content_type_from_ext=True,
    )

    return app


def _wrap_app(app):
    app = request_id.RequestId(app)
    if cfg.CONF.pecan.auth_enable and cfg.CONF.auth_strategy == "keystone":
        conf = dict(cfg.CONF.keystone_authtoken)
        # Change auth decisions of requests to the app itself.
        conf.update({"delay_auth_decision": True})

        # NOTE: Policy enforcement works only if Keystone
        # authentication is enabled. No support for other authentication
        # types at this point.
        return auth_token.AuthProtocol(app, conf)
    else:
        return app


_launcher = None


def serve(api_service, conf, workers=1):
    global _launcher
    if _launcher:
        raise RuntimeError(_("serve() can only be called once"))

    _launcher = service.launch(conf, api_service, workers=workers)


def wait():
    _launcher.wait()
