===============================
api
===============================

DC DBsync API is Web Server Gateway Interface (WSGI) application to receive
and process API calls, including keystonemiddleware to do the authentication,
parameter check and validation. It receives API calls from DC Orchestrator
to read/write/update resources in Databases on behalf of DC Orchestrator.
The API calls are processed in synchronous way, so that the caller will wait
for the response to come back.

Multiple DC DBsync API could run in parallel, and also can work in
multi-worker mode.

Multiple DC DBsync API is designed and run in stateless mode.

Setup and encapsulate the API WSGI app

app.py:
    Setup and encapsulate the API WSGI app, including integrate the
    keystonemiddleware app

api_config.py:
    API configuration loading and init

enforcer.py
    Enforces policies on the version2 APIs
