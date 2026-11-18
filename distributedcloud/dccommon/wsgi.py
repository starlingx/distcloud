# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import socket
import time

import gunicorn.app.base
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class RequestLogMiddleware(object):
    """WSGI middleware that logs HTTP requests through oslo_log.

    Logs the HTTP method, path, response status code, and elapsed time
    for each request processed by the application.
    """

    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        start = time.monotonic()
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        query = environ.get("QUERY_STRING", "")
        if query:
            path = "%s?%s" % (path, query)

        status_code = None

        def logging_start_response(status, response_headers, *args):
            nonlocal status_code
            status_code = status.split(" ", 1)[0]
            return start_response(status, response_headers, *args)

        try:
            return self.application(environ, logging_start_response)
        finally:
            elapsed = time.monotonic() - start
            LOG.info(
                "%(method)s %(path)s status: %(status)s time: %(elapsed).3fs",
                {
                    "method": method,
                    "path": path,
                    "status": status_code or "-",
                    "elapsed": elapsed,
                },
            )


class DCApplication(gunicorn.app.base.BaseApplication):
    """Gunicorn application for Distributed Cloud API services.

    Launches a WSGI application using gunicorn with gthread workers.
    Configuration is read from oslo.config options.
    """

    def __init__(self, app, name, host, port, workers=1, post_worker_init_hook=None):
        self.application = RequestLogMiddleware(app)
        self.name = name
        self.host = host
        self.port = port
        self.workers = workers
        self._post_worker_init_hook = post_worker_init_hook
        super().__init__()

    def _get_bind_address(self):
        """Resolve the host into a gunicorn bind string.

        Gunicorn creates an IPv4 socket for any host that is not an IPv6
        literal, so a hostname that only resolves to IPv6 fails to bind.
        Resolve it here and bracket IPv6 results.
        """
        family, _, _, _, sockaddr = socket.getaddrinfo(
            self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )[0]
        address = sockaddr[0]
        if family == socket.AF_INET6:
            address = "[%s]" % address
        return "%s:%s" % (address, self.port)

    def load_config(self):
        self.cfg.set("bind", self._get_bind_address())
        self.cfg.set("workers", self.workers)
        self.cfg.set("worker_class", "gthread")
        # Setting 100 threads to mimic previous wsgi from oslo_service
        self.cfg.set("threads", 100)
        self.cfg.set("graceful_timeout", 600)
        self.cfg.set("accesslog", None)
        self.cfg.set("proc_name", self.name)
        if self._post_worker_init_hook:
            self.cfg.set("post_worker_init", self._post_worker_init_hook)

    def load(self):
        return self.application
