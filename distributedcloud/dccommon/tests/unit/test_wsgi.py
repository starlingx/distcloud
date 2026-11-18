# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import socket

import mock
from oslotest import base

from dccommon import wsgi


class TestRequestLogMiddleware(base.BaseTestCase):
    """Tests for the RequestLogMiddleware class."""

    def setUp(self):
        super(TestRequestLogMiddleware, self).setUp()
        self.mock_app = mock.MagicMock()
        self.middleware = wsgi.RequestLogMiddleware(self.mock_app)

    def _make_environ(self, method="GET", path="/test", query=""):
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
        }
        if query:
            environ["QUERY_STRING"] = query
        return environ

    def test_init_stores_application(self):
        """Test that the middleware stores the wrapped application."""
        self.assertIs(self.middleware.application, self.mock_app)

    @mock.patch.object(wsgi, "LOG")
    def test_calls_underlying_application(self, mock_log):
        """Test that the middleware forwards the call to the wrapped app."""
        environ = self._make_environ()
        start_response = mock.MagicMock()
        self.mock_app.return_value = [b"response"]

        result = self.middleware(environ, start_response)

        self.assertEqual([b"response"], result)
        self.mock_app.assert_called_once()
        call_args = self.mock_app.call_args
        self.assertEqual(environ, call_args[0][0])

    @mock.patch.object(wsgi, "LOG")
    def test_logs_request_info(self, mock_log):
        """Test that method, path, status, and time are logged."""
        environ = self._make_environ(method="POST", path="/v1/resources")
        start_response = mock.MagicMock()

        def fake_app(env, sr):
            sr("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        middleware = wsgi.RequestLogMiddleware(fake_app)
        middleware(environ, start_response)

        mock_log.info.assert_called_once()
        log_fmt, log_args = mock_log.info.call_args[0]
        self.assertEqual("POST", log_args["method"])
        self.assertEqual("/v1/resources", log_args["path"])
        self.assertEqual("200", log_args["status"])
        self.assertIn("elapsed", log_args)
        self.assertGreaterEqual(log_args["elapsed"], 0)

    @mock.patch.object(wsgi, "LOG")
    def test_logs_query_string(self, mock_log):
        """Test that the query string is included in the logged path."""
        environ = self._make_environ(
            method="GET", path="/v1/resources", query="limit=10"
        )
        start_response = mock.MagicMock()

        def fake_app(env, sr):
            sr("200 OK", [])
            return [b"ok"]

        middleware = wsgi.RequestLogMiddleware(fake_app)
        middleware(environ, start_response)

        log_args = mock_log.info.call_args[0][1]
        self.assertEqual("/v1/resources?limit=10", log_args["path"])

    @mock.patch.object(wsgi, "LOG")
    def test_logs_status_dash_when_start_response_not_called(self, mock_log):
        """Test that status is '-' if the app never calls start_response."""
        environ = self._make_environ()
        start_response = mock.MagicMock()

        def fake_app(env, sr):
            return [b"data"]

        middleware = wsgi.RequestLogMiddleware(fake_app)
        middleware(environ, start_response)

        log_args = mock_log.info.call_args[0][1]
        self.assertEqual("-", log_args["status"])

    @mock.patch.object(wsgi, "LOG")
    def test_logs_even_on_app_exception(self, mock_log):
        """Test that request is logged even if the app raises an exception."""
        environ = self._make_environ(method="DELETE", path="/v1/resources/1")
        start_response = mock.MagicMock()

        def failing_app(env, sr):
            raise RuntimeError("boom")

        middleware = wsgi.RequestLogMiddleware(failing_app)

        self.assertRaises(RuntimeError, middleware, environ, start_response)

        mock_log.info.assert_called_once()
        log_args = mock_log.info.call_args[0][1]
        self.assertEqual("DELETE", log_args["method"])
        self.assertEqual("/v1/resources/1", log_args["path"])
        self.assertEqual("-", log_args["status"])

    @mock.patch.object(wsgi, "LOG")
    def test_passes_start_response_return_value(self, mock_log):
        """Test that the write callable from start_response is propagated."""
        environ = self._make_environ()
        write_callable = mock.MagicMock()
        start_response = mock.MagicMock(return_value=write_callable)

        captured_write = []

        def fake_app(env, sr):
            w = sr("200 OK", [])
            captured_write.append(w)
            return [b"ok"]

        middleware = wsgi.RequestLogMiddleware(fake_app)
        middleware(environ, start_response)

        start_response.assert_called_once()
        self.assertIs(captured_write[0], write_callable)


class TestDCApplication(base.BaseTestCase):
    """Tests for the DCApplication class."""

    @mock.patch("gunicorn.app.base.BaseApplication.__init__")
    def test_init_wraps_app_with_middleware(self, mock_super_init):
        """Test that DCApplication wraps the app with RequestLogMiddleware."""
        mock_super_init.return_value = None
        app = mock.MagicMock()

        dc_app = wsgi.DCApplication(app, "TestApp", "0.0.0.0", 8080)

        self.assertIsInstance(dc_app.application, wsgi.RequestLogMiddleware)
        self.assertIs(dc_app.application.application, app)

    @mock.patch("gunicorn.app.base.BaseApplication.__init__")
    def test_init_stores_attributes(self, mock_super_init):
        """Test that DCApplication stores name, host, port, and workers."""
        mock_super_init.return_value = None
        app = mock.MagicMock()

        dc_app = wsgi.DCApplication(app, "TestApp", "0.0.0.0", 8080, workers=4)

        self.assertEqual("TestApp", dc_app.name)
        self.assertEqual("0.0.0.0", dc_app.host)
        self.assertEqual(8080, dc_app.port)
        self.assertEqual(4, dc_app.workers)

    @mock.patch("gunicorn.app.base.BaseApplication.__init__")
    def test_load_returns_application(self, mock_super_init):
        """Test that load() returns the middleware-wrapped application."""
        mock_super_init.return_value = None
        app = mock.MagicMock()

        dc_app = wsgi.DCApplication(app, "TestApp", "0.0.0.0", 8080)

        self.assertIs(dc_app.load(), dc_app.application)

    @mock.patch.object(wsgi.socket, "getaddrinfo")
    @mock.patch("gunicorn.app.base.BaseApplication.__init__")
    def test_load_config_sets_expected_values(self, mock_super_init, mock_getaddrinfo):
        """Test that load_config sets all gunicorn configuration values."""
        mock_super_init.return_value = None
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", 8080))
        ]
        app = mock.MagicMock()

        dc_app = wsgi.DCApplication(app, "TestApp", "0.0.0.0", 8080, workers=2)
        dc_app.cfg = mock.MagicMock()
        dc_app.load_config()

        dc_app.cfg.set.assert_any_call("bind", "0.0.0.0:8080")
        dc_app.cfg.set.assert_any_call("workers", 2)
        dc_app.cfg.set.assert_any_call("worker_class", "gthread")
        dc_app.cfg.set.assert_any_call("threads", 100)
        dc_app.cfg.set.assert_any_call("accesslog", None)
        dc_app.cfg.set.assert_any_call("proc_name", "TestApp")

    def _make_app_with_cfg(self, host, port):
        with mock.patch("gunicorn.app.base.BaseApplication.__init__") as m:
            m.return_value = None
            dc_app = wsgi.DCApplication(mock.MagicMock(), "TestApp", host, port)
        dc_app.cfg = mock.MagicMock()
        return dc_app

    @mock.patch.object(wsgi.socket, "getaddrinfo")
    def test_load_config_resolves_ipv6_only_hostname(self, mock_getaddrinfo):
        """Test that a hostname resolving to IPv6 is bound as a bracketed IP."""
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2620:10a:a001:aa2f::d00", 25497, 0, 0),
            )
        ]
        dc_app = self._make_app_with_cfg("controller.internal", 25497)

        dc_app.load_config()

        mock_getaddrinfo.assert_called_once_with(
            "controller.internal", 25497, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        dc_app.cfg.set.assert_any_call("bind", "[2620:10a:a001:aa2f::d00]:25497")

    @mock.patch.object(wsgi.socket, "getaddrinfo")
    def test_load_config_resolves_ipv4_hostname(self, mock_getaddrinfo):
        """Test that a hostname resolving to IPv4 is bound as a plain IP."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.204.1", 25497))
        ]
        dc_app = self._make_app_with_cfg("controller.internal", 25497)

        dc_app.load_config()

        dc_app.cfg.set.assert_any_call("bind", "192.168.204.1:25497")

    @mock.patch.object(wsgi.socket, "getaddrinfo")
    def test_load_config_brackets_ipv6_literal(self, mock_getaddrinfo):
        """Test that an unbracketed IPv6 literal host is bracketed."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 8080, 0, 0))
        ]
        dc_app = self._make_app_with_cfg("::1", 8080)

        dc_app.load_config()

        mock_getaddrinfo.assert_called_once_with(
            "::1", 8080, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        dc_app.cfg.set.assert_any_call("bind", "[::1]:8080")

    @mock.patch("gunicorn.app.base.BaseApplication.__init__")
    def test_default_workers_is_one(self, mock_super_init):
        """Test that the default number of workers is 1."""
        mock_super_init.return_value = None
        app = mock.MagicMock()

        dc_app = wsgi.DCApplication(app, "TestApp", "0.0.0.0", 8080)

        self.assertEqual(1, dc_app.workers)
