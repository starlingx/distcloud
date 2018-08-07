===============================
api
===============================

DC Manager API is Web Server Gateway Interface (WSGI) application to receive
and process API calls, including keystonemiddleware to do the authentication,
parameter check and validation, convert API calls to job rpc message, and
then send the job to DC Manager Manager through the queue. If the job will
be processed by DC Manager Manager in synchronous way, the DC Manager API will
wait for the response from the DC Manager Manager. Otherwise, the DC Manager
API will send response to the API caller first, and then send the job to
DC Manager Manager in asynchronous way.

Multiple DC Manager API could run in parallel, and also can work in
multi-worker mode.

Multiple DC Manager API will be designed and run in stateless mode, persistent
data will be accessed (read and write) from the DC Manager Database through
the DAL module.

Setup and encapsulate the API WSGI app

app.py:
    Setup and encapsulate the API WSGI app, including integrate the
    keystonemiddleware app

api_config.py:
    API configuration loading and init

enforcer.py
    Enforces policies on the version2 APIs
