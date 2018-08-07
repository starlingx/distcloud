===============================
Service
===============================

Distributed Cloud Orchestration Engine Service has responsibility for:

    Monitoring the subcloud status, and return the result if needed.

    There is a single engine, with each subcloud having one persistent
    sync thread per endpoint-type.  Sync audit threads will be created
    on demand as needed.

service.py:
    run orchengine service, and establish RPC server

generic_sync_manager.py
    Manages all the generic resource syncing.
