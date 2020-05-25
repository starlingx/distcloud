====================================================
Dcmanager API v1
====================================================

Manage distributed cloud operations with the dcmanager API.

The typical port used for the dcmanager REST API is 8119. However,
proper technique would be to look up the dcmanager service endpoint in
Keystone.

-------------
API versions
-------------

****************************************************
Lists information about all dcmanager API versions
****************************************************

.. rest_method:: GET /

**Normal response codes**

200, 300

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

::

   {
     "versions": [
       {
         "status": "CURRENT",
         "updated": "2017-10-2",
         "id": "v1.0",
         "links": [
           {
             "href": "http://192.168.204.2:8119/v1.0/",
             "rel": "self"
           }
         ]
       }
     ]
   }

This operation does not accept a request body.

----------
Subclouds
----------

Subclouds are systems managed by a central System Controller.

*********************
Lists all subclouds
*********************

.. rest_method:: GET /v1.0/subclouds

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subclouds (Optional)", "plain", "xsd:list", "The list of subclouds."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud."
   "management (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "availability (Optional)", "plain", "xsd:string", "Availability status of the subcloud."
   "management-subnet (Optional)", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-start-ip (Optional)", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "management-end-ip (Optional)", "plain", "xsd:string", "End of management IP address range for subcloud."
   "systemcontroller-gateway-ip (Optional)", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "endpoint_sync_status (Optional)", "plain", "xsd:list", "The list of endpoint sync statuses."
   "platform_sync_status (Optional)", "plain", "xsd:string", "The platform sync status of the subcloud."
   "volume_sync_status (Optional)", "plain", "xsd:string", "The volume sync status of the subcloud."
   "compute_sync_status (Optional)", "plain", "xsd:string", "The compute sync status of the subcloud."
   "network_sync_status (Optional)", "plain", "xsd:string", "The network sync status of the subcloud."
   "patching_sync_status (Optional)", "plain", "xsd:string", "The patching sync status of the subcloud."
   "group_id (Optional)", "plain", "xsd:int", "The unique identifier for the subcloud group for this subcloud."

::

   {
     "subclouds": [
       {
          "description": None,
          "management-start-ip": "192.168.204.50",
          "sync_status": "unknown",
          "updated-at": None,
          "software-version": "18.01",
          "management-state": "unmanaged",
          "availability-status": "offline",
          "management-subnet": "192.168.204.0/24",
          "systemcontroller-gateway-ip": "192.168.204.101",
          "subcloud_id": 1,
          "location": None,
          "endpoint_sync_status": [
            {
              "sync_status": "unknown",
              "endpoint_type": "platform"
            },
            {
              "sync_status": "unknown",
              "endpoint_type": "volume"
            },
            {
              "sync_status":  "unknown",
              "endpoint_type":  "compute"
            },
            {
              "sync_status": "unknown",
              "endpoint_type": "network"
            },
            {
              "sync_status": "unknown",
              "endpoint_type": "patching"
            },
          "created-at": u"2018-02-25 19:06:35.208505",
          "group_id": 1,
          "management-gateway-ip": u"192.168.204.1",
          "management-end-ip": u"192.168.204.100",
          "id": 1,
          "name": "subcloud6"
       },
       {
          "description": "test subcloud",
          "management-start-ip": "192.168.205.50",
          "sync_status": "in-sync",
          "updated-at": None,
          "software-version": "18.01",
          "management-state": "managed",
          "availability-status": "online",
          "management-subnet": "192.168.205.0/24",
          "systemcontroller-gateway-ip": "192.168.205.101",
          "subcloud_id": 2,
          "location": "Ottawa,
          "endpoint_sync_status": [
            {
              "sync_status": "in-sync",
              "endpoint_type": "platform"
            },
            {
              "sync_status": "in-sync",
              "endpoint_type": "volume"
            },
            {
              "sync_status":  "in-sync",
              "endpoint_type":  "compute"
            },
            {
              "sync_status": "in-sync",
              "endpoint_type": "network"
            },
            {
              "sync_status": "out-of-sync",
              "endpoint_type": "patching"
            },
          "created-at": "2018-02-25 19:06:35.208505",
          "group_id": 1,
          "management-gateway-ip": "192.168.205.1",
          "management-end-ip": "192.168.205.100",
          "id": 2,
          "name": "subcloud7"
       },
     ]
   }

This operation does not accept a request body.

******************
Creates a subcloud
******************

.. rest_method:: POST /v1.0/subclouds

Accepts Content-Type multipart/form-data.


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "bootstrap-address", "plain", "xsd:string", "An OAM IP address of the subcloud controller-0."
   "sysadmin_password", "plain", "xsd:string", "The sysadmin password of the subcloud. Must be base64 encoded."
   "bmc_password (optional)", "plain", "xsd:string", "The BMC password of the subcloud. Must be base64 encoded."
   "bootstrap_values", "plain", "xsd:string", "The content of a file containing the bootstrap overrides such as subcloud name, management and OAM subnet."
   "install_values (Optional)", "plain", "xsd:string", "The content of a file containing install variables such as subcloud bootstrap interface and BMC information."
   "deploy_config (Optional)", "plain", "xsd:string", "The content of a file containing the resource definitions describing the desired subcloud configuration."
   "group_id", "plain", "xsd:int", "Id of the subcloud group. Defaults to 1."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud."
   "management (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "availability (Optional)", "plain", "xsd:string", "Availability status of the subcloud."
   "management-subnet (Optional)", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-start-ip (Optional)", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "management-end-ip (Optional)", "plain", "xsd:string", "End of management IP address range for subcloud."
   "systemcontroller-gateway-ip (Optional)", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "group_id (Optional)", "plain", "xsd:int", "Id of the subcloud group."

::

   {
     "name": "subcloud7",
     "management-start-ip": "192.168.205.110",
     "systemcontroller-gateway-ip": "192.168.204.102",
     "location": "West Ottawa",
     "management-subnet": "192.168.205.0/24",
     "management-gateway-ip": "192.168.205.1",
     "management-end-ip": "192.168.205.160",
     "group_id": 1,
     "description": "new subcloud"
   }

::

   {
     "description": None,
     "management-start-ip": "192.168.205.110",
     "created-at": "2018-02-25T22:17:11.845596",
     "updated-at": None,
     "software-version": "18.01",
     "management-state": "unmanaged",
     "availability-status": "offline",
     "systemcontroller-gateway-ip": "192.168.204.102",
     "location": None,
     "group_id": 1,
     "management-subnet": "192.168.205.0/24",
     "management-gateway-ip": "192.168.205.1",
     "management-end-ip": "192.168.205.160",
     "id": 4,
     "name": "subcloud7"
   }

******************************************************
Shows information about a specific subcloud
******************************************************

.. rest_method:: GET /v1.0/subclouds/​{subcloud}​

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud."
   "management (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "availability (Optional)", "plain", "xsd:string", "Availability status of the subcloud."
   "management-subnet (Optional)", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-start-ip (Optional)", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "management-end-ip (Optional)", "plain", "xsd:string", "End of management IP address range for subcloud."
   "systemcontroller-gateway-ip (Optional)", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "endpoint_sync_status (Optional)", "plain", "xsd:list", "The list of endpoint sync statuses."
   "platform_sync_status (Optional)", "plain", "xsd:string", "The platform sync status of the subcloud."
   "volume_sync_status (Optional)", "plain", "xsd:string", "The volume sync status of the subcloud."
   "compute_sync_status (Optional)", "plain", "xsd:string", "The compute sync status of the subcloud."
   "network_sync_status (Optional)", "plain", "xsd:string", "The network sync status of the subcloud."
   "patching_sync_status (Optional)", "plain", "xsd:string", "The patching sync status of the subcloud."
   "group_id (Optional)", "plain", "xsd:int", "Id of the subcloud group."

::

   {
     "description": "test subcloud",
     "management-start-ip": "192.168.204.50",
     "created-at": "2018-02-25 19:06:35.208505",
     "updated-at": "2018-02-25 21:35:59.771779",
     "software-version": "18.01",
     "deploy-status": "not-deployed",
     "management-state": "unmanaged",
     "availability-status": "offline",
     "management-subnet": "192.168.204.0/24",
     "systemcontroller-gateway-ip": "192.168.204.101",
     "openstack-installed": false,
     "location": "ottawa",
     "endpoint_sync_status": [
       {
         "sync_status": "in-sync",
         "endpoint_type": "identity"
       },
       {
         "sync_status": "in-sync",
         "endpoint_type": "load"
       },
       {
         "sync_status": "in-sync",
         "endpoint_type": "patching"
       },
       {
         "sync_status": "in-sync",
         "endpoint_type": "platform"
       }
     ],
     "management-gateway-ip": "192.168.204.1",
     "management-end-ip": "192.168.204.100",
     "group_id": 1,
     "id": 1,
     "name": "subcloud6"
   }

This operation does not accept a request body.

******************************************************
Shows additional information about a specific subcloud
******************************************************

.. rest_method:: GET /v1.0/subclouds/​{subcloud}​/detail

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. csv-table::
      :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."

**Response parameters**

.. csv-table::
      :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud."
   "management (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "availability (Optional)", "plain", "xsd:string", "Availability status of the subcloud."
   "management-subnet (Optional)", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-start-ip (Optional)", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "management-end-ip (Optional)", "plain", "xsd:string", "End of management IP address range for subcloud."
   "systemcontroller-gateway-ip (Optional)", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "endpoint_sync_status (Optional)", "plain", "xsd:list", "The list of endpoint sync statuses."
   "platform_sync_status (Optional)", "plain", "xsd:string", "The platform sync status of the subcloud."
   "volume_sync_status (Optional)", "plain", "xsd:string", "The volume sync status of the subcloud."
   "compute_sync_status (Optional)", "plain", "xsd:string", "The compute sync status of the subcloud."
   "network_sync_status (Optional)", "plain", "xsd:string", "The network sync status of the subcloud."
   "patching_sync_status (Optional)", "plain", "xsd:string", "The patching sync status of the subcloud."
   "oam_floating_ip (Optional)", "plain", "xsd:string", "OAM Floating IP of the subcloud."
   "group_id (Optional)", "plain", "xsd:int", "Id of the subcloud group."

::

   {
     "description": "test subcloud",
     "management-start-ip": "192.168.204.50",
     "created-at": "2018-02-25 19:06:35.208505",
     "updated-at": "2018-02-25 21:35:59.771779",
     "software-version": "18.01",
     "management-state": "unmanaged",
     "availability-status": "offline",
     "deploy-status": "not-deployed",
     "management-subnet": "192.168.204.0/24",
     "systemcontroller-gateway-ip": "192.168.204.101",
     "openstack-installed": false,
     "location": "ottawa",
     "endpoint_sync_status": [
       {
         "sync_status": "in-sync",
         "endpoint_type": "identity"
       },
       {
         "sync_status": "in-sync",
         "endpoint_type": "load"
       },
       {
         "sync_status": "in-sync",
         "endpoint_type": "patching"
       },
       {
         "sync_status": "in-sync",
         "endpoint_type": "platform"
       }
     ],
     "management-gateway-ip": "192.168.204.1",
     "management-end-ip": "192.168.204.100",
     "group_id": 1,
     "id": 1,
     "name": "subcloud6",
     "oam_floating_ip" "10.10.10.12"
   }

This operation does not accept a request body.

******************************
Modifies a specific subcloud
******************************

.. rest_method:: PATCH /v1.0/subclouds/​{subcloud}​

The attributes of a subcloud which are modifiable:

-  description

-  location

-  management-state

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."
   "description (Optional)", "plain", "xsd:string", "The description of the subcloud."
   "location (Optional)", "plain", "xsd:string", "The location of the subcloud."
   "management-state (Optional)", "plain", "xsd:string", "The management-state of the subcloud, ``managed`` or ``unmanaged``. The subcloud must be online before this can be modified to managed."
   "group_id (Optional)", "plain", "xsd:int", "Id of the subcloud group. The group must exist."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud."
   "management (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "availability (Optional)", "plain", "xsd:string", "Availability status of the subcloud."
   "management-subnet (Optional)", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-start-ip (Optional)", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "management-end-ip (Optional)", "plain", "xsd:string", "End of management IP address range for subcloud."
   "systemcontroller-gateway-ip (Optional)", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "group_id (Optional)", "plain", "xsd:int", "Id of the subcloud group."

::

   {
     "description": "new description",
     "location": "new location",
     "management-state": "managed"
     "group_id": 2,
   }

::

   {
     "description": "new description",
     "management-start-ip": "192.168.204.50",
     "created-at": "2018-02-25T19:06:35.208505",
     "updated-at": "2018-02-25T23:01:17.490090",
     "software-version": "18.01",
     "management-state": "unmanaged",
     "openstack-installed": false,
     "availability-status": "offline",
     "deploy-status": "not-deployed",
     "systemcontroller-gateway-ip": "192.168.204.101",
     "location": "new location",
     "management-subnet": "192.168.204.0/24",
     "management-gateway-ip": "192.168.204.1",
     "management-end-ip": "192.168.204.100",
     "group_id": 2,
     "id": 1,
     "name": "subcloud6"
   }

**********************************
Reconfigures a specific subcloud
**********************************

.. rest_method:: PATCH /v1.0/subclouds/<200b>{subcloud}<200b>/reconfigure

The attributes of a subcloud which are modifiable:

-  subcloud configuration (which is provided through deploy_config file)

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
         :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."
   "deploy_config", "plain", "xsd:string", "The content of a file containing the resource definitions describing the desired subcloud configuration."
   "sysadmin_password", "plain", "xsd:string", "The sysadmin password of the subcloud. Must be base64 encoded."

**Response parameters**

.. csv-table::
         :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id", "plain", "xsd:int", "The unique identifier for this object."
   "created_at", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name", "plain", "xsd:string", "The name provisioned for the subcloud."
   "description", "plain", "xsd:string", "The description of the subcloud."
   "location", "plain", "xsd:string", "The location of the subcloud."
   "software-version", "plain", "xsd:string", "The software version of the subcloud."
   "deploy_status", "plain", "xsd:string", "The deployment status of the subcloud."
   "management (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "availability", "plain", "xsd:string", "Availability status of the subcloud."
   "management-subnet", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-start-ip", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "management-end-ip", "plain", "xsd:string", "End of management IP address range for subcloud."
   "systemcontroller-gateway-ip", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "group_id", "plain", "xsd:int", "Id of the subcloud group."

Accepts Content-Type multipart/form-data

::

   {
     "description": "subcloud description",
     "management-start-ip": "192.168.204.50",
     "created-at": "2018-02-25T19:06:35.208505",
     "updated-at": "2018-02-25T23:01:17.490090",
     "software-version": "20.06",
     "management-state": "unmanaged",
     "availability-status": "offline",
     "openstack-installed": false,
     "deploy-status": "pre-deploy",
     "systemcontroller-gateway-ip": "192.168.204.101",
     "location": "location",
     "management-subnet": "192.168.204.0/24",
     "management-gateway-ip": "192.168.204.1",
     "management-end-ip": "192.168.204.100",
     "group_id": 2,
     "id": 1,
     "name": "subcloud6"
   }

*****************************
Deletes a specific subcloud
*****************************

.. rest_method:: DELETE /v1.0/subclouds/​{subcloud}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."

This operation does not accept a request body.

----------------
Subcloud Groups
----------------

Subcloud Groups are a logical grouping managed by a central System Controller.
Subclouds in a group can be updated in parallel when applying patches or
software upgrades.

**************************
Lists all subcloud groups
**************************

.. rest_method:: GET /v1.0/subcloud-groups

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud_groups (Optional)", "plain", "xsd:list", "The list of subcloud groups."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "name (Optional)", "plain", "xsd:string", "The unique name for the subcloud group."
   "description (Optional)", "plain", "xsd:string", "The description of the subcloud group."
   "update_apply_type (Optional)", "plain", "xsd:string", "The method for applying an update. ```serial``` or ```parallel```."
   "max_parallel_subclouds (Optional)", "plain", "xsd:int", "The maximum number of subclouds to update in parallel."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "subcloud_groups": [
       {
         "update_apply_type": "parallel",
         "description": "Default Subcloud Group",
         "updated-at": null,
         "created-at": null,
         "max_parallel_subclouds": 2,
         "id": 1,
         "name": "Default"
       },
     ]
   }

This operation does not accept a request body.

*************************
Creates a subcloud group
*************************

.. rest_method:: POST /v1.0/subcloud-groups

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name for the subcloud group. Must be unique."
   "description (Optional)", "plain", "xsd:string", "The description of the subcloud group."
   "update_apply_type (Optional)", "plain", "xsd:string", "The method for applying an update. Must be ```serial``` or ```parallel```."
   "max_parallel_subclouds (Optional)", "plain", "xsd:int", "The maximum number of subclouds to update in parallel. Must be greater than 0."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "name (Optional)", "plain", "xsd:string", "The unique name for the subcloud group."
   "description (Optional)", "plain", "xsd:string", "The description of the subcloud group."
   "update_apply_type (Optional)", "plain", "xsd:string", "The method for applying an update. ```serial``` or ```parallel```."
   "max_parallel_subclouds (Optional)", "plain", "xsd:int", "The maximum number of subclouds to update in parallel."

::

   {
     "name": "GroupX",
     "description": "A new group",
     "update_apply_type": "parallel",
     "max_parallel_subclouds": 3
   }

::

   {
     "id": 2,
     "name": "GroupX",
     "description": "A new group",
     "update_apply_type": "parallel",
     "max_parallel_subclouds": "3",
     "updated-at": null,
     "created-at": "2020-04-08 15:15:10.750592",
   }

******************************************************
Shows information about a specific subcloud group
******************************************************

.. rest_method:: GET /v1.0/subcloud-groups/​{subcloud-group}​

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-group", "URI", "xsd:string", "The subcloud group reference, name or id."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud group."
   "description (Optional)", "plain", "xsd:string", "The description for the subcloud group."
   "max_parallel_subclouds (Optional)", "plain", "xsd:int", "The maximum number of subclouds to update in parallel."
   "update_apply_type (Optional)", "plain", "xsd:string", "The update apply type for the subcloud group: ```serial``` or ```parallel```."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "id": 2,
     "name": "GroupX",
     "description": "A new group",
     "max_parallel_subclouds": 3,
     "update_apply_type": "parallel",
     "created-at": "2020-04-08 15:15:10.750592",
     "updated-at": null
   }

This operation does not accept a request body.

******************************************************
Shows subclouds that are part of a subcloud group
******************************************************

.. rest_method:: GET /v1.0/subcloud-groups/​{subcloud-group}​/subclouds

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-group", "URI", "xsd:string", "The subcloud group reference, name or id."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subclouds (Optional)", "plain", "xsd:list", "The list of subclouds."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for a subcloud."
   "group_id (Optional)", "plain", "xsd:int", "The unique identifier for the subcloud group."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud."
   "management-state (Optional)", "plain", "xsd:string", "Management state of the subcloud."
   "management-start-ip (Optional)", "plain", "xsd:string", "Start of management IP address range for subcloud."
   "software-version (Optional)", "plain", "xsd:string", "Software version for subcloud."
   "availability-status (Optional)", "plain", "xsd:string", "Availability status of the subcloud."
   "systemcontroller-gateway-ip (Optional)", "plain", "xsd:string", "Systemcontroller gateway IP Address."
   "location (Optional)", "plain", "xsd:string", "The location provisioned for the subcloud."
   "openstack-installed (Optional)", "plain", "xsd:boolean", "Whether openstack is installed on the subcloud."
   "management-subnet (Optional)", "plain", "xsd:string", "Management subnet for subcloud in CIDR format."
   "management-gateway-ip (Optional)", "plain", "xsd:string", "Management gateway IP for subcloud."
   "management-end-ip (Optional)", "plain", "xsd:string", "End of management IP address range for subcloud."
   "description (Optional)", "plain", "xsd:string", "The description provisioned for the subcloud."

::

   {
     "subclouds": [
       {
         "deploy-status": "complete",
         "id": 1,
         "group_id": 2,
         "created-at": "2020-04-13 13:16:21.903294",
         "updated-at": "2020-04-13 13:36:27.494056",
         "name": "subcloud1",
         "management-state": "unmanaged",
         "management-start-ip": "192.168.101.2",
         "software-version": "20.01",
         "availability-status": "offline",
         "systemcontroller-gateway-ip": "192.168.204.101",
         "location": "YOW",
         "openstack-installed": false,
         "management-subnet": "192.168.101.0/24",
         "management-gateway-ip": "192.168.101.1",
         "management-end-ip": "192.168.101.50",
         "description": "Ottawa Site"
      }
     ]
   }

This operation does not accept a request body.

***********************************
Modifies a specific subcloud group
***********************************

.. rest_method:: PATCH /v1.0/subcloud-groups/​{subcloud-group}​

The attributes of a subcloud group which are modifiable:

-  name

-  description

-  update_apply_type

-  max_parallel_subclouds

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-group", "URI", "xsd:string", "The subcloud group reference, name or id."
   "name (Optional)", "plain", "xsd:string", "The name of the subcloud group. Must be unique."
   "description (Optional)", "plain", "xsd:string", "The description of the subcloud group."
   "update_apply_type (Optional)", "plain", "xsd:string", "The update apply type for the subcloud group. Either ```serial``` or ```parallel```."
   "max_parallel_subclouds (Optional)", "plain", "xsd:int", "The number of subclouds to update in parallel. Must be greater than 0."

**Response parameters**

.. csv-table::
      :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud group."
   "description (Optional)", "plain", "xsd:string", "The description for the subcloud group."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "description": "new description",
     "update_apply_type": "serial",
     "max_parallel_subclouds": 5
   }

::

   {
     "id": 2,
     "name": "GroupX",
     "description": "new description",
     "update_apply_type": "serial",
     "max_parallel_subclouds": 5,
     "created-at": "2020-04-08 15:15:10.750592",
     "updated-at": "2020-04-08 15:21:01.527101"
   }

**********************************
Deletes a specific subcloud group
**********************************

.. rest_method:: DELETE /v1.0/subcloud-groups/​{subcloud-group}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-group", "URI", "xsd:string", "The subcloud group reference, name or id."

This operation does not accept a request body.

----------------
Subcloud Alarms
----------------

Subcloud alarms are aggregated on the System Controller.

**************************************
Summarizes alarms from all subclouds
**************************************

.. rest_method:: GET /v1.0/alarms

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "alarm_summary (Optional)", "plain", "xsd:list", "The list of alarm summaries."
   "uuid (Optional)", "plain", "csapi:UUID", "The unique identifier for this object."
   "region_name (Optional)", "plain", "xsd:string", "The name provisioned for the subcloud (synonym for subcloud name)."
   "cloud_status (Optional)", "plain", "xsd:string", "The overall alarm status of the cloud."
   "warnings (Optional)", "plain", "xsd:int", "The number of warnings for the cloud (-1 when the cloud_status is disabled)."
   "minor_alarms (Optional)", "plain", "xsd:int", "The number of minor alarms for the cloud (-1 when the cloud_status is disabled)."
   "critical_alarms (Optional)", "plain", "xsd:int", "The number of critical alarms for the cloud (-1 when the cloud_status is disabled)."
   "major_alarms (Optional)", "plain", "xsd:int", "The number of major alarms for the cloud (-1 when the cloud_status is disabled)."

::

   {
     "alarm_summary": [
       {
         "cloud_status": "disabled",
         "region_name": "subcloud6",
         "warnings": -1,
         "minor_alarms": -1,
         "critical_alarms": -1,
         "major_alarms": -1,
         "uuid": "32b9233e-d993-45fb-96eb-5bfa9b1cad5d"
       }
     ]
   }

This operation does not accept a request body.

------------------------
Subcloud Patch Strategy
------------------------

The Subcloud patch strategy is configurable.

*****************************************
Shows the details of the patch strategy
*****************************************

.. rest_method:: GET /v1.0/sw-update-strategy

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-apply-type (Optional)", "plain", "xsd:string", "Subcloud apply type"
   "state (Optional)", "plain", "xsd:string", "The state of patching."
   "stop-on-failure (Optional)", "plain", "xsd:string", "Whether to stop patching on failure or not."
   "type (Optional)", "plain", "xsd:string", "Will be set to: ``patch``."
   "max-parallel-subclouds (Optional)", "plain", "xsd:int", "The number of subclouds to patch in parallel."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "max-parallel-subclouds": 2,
     "updated-at": None,
     "created-at": "2018-02-25T23:23:53.852473",
     "subcloud-apply-type": "serial",
     "state": "initial",
     "stop-on-failure": True,
     "type": "patch",
     "id": 2
   }

This operation does not accept a request body.

****************************
Creates the patch strategy
****************************

.. rest_method:: POST /v1.0/sw-update-strategy

-  subcloud-apply-type,

-  max-parallel-subclouds,

-  stop-on-failure,

-  cloud_name,

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-apply-type (Optional)", "plain", "xsd:string", "Subcloud apply type, ``parallel`` or ``serial``."
   "max-parallel-subclouds (Optional)", "plain", "xsd:string", "Maximum number of parallel subclouds."
   "stop-on-failure (Optional)", "plain", "xsd:string", "Whether stop patching any additional subclouds after a failure or not, ``True`` or ``False``."
   "cloud_name (Optional)", "plain", "xsd:string", "Name of a single cloud to patch."
   "type (Optional)", "plain", "xsd:string", "Must be set to: ``patch``."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-apply-type (Optional)", "plain", "xsd:string", "Subcloud apply type"
   "state (Optional)", "plain", "xsd:string", "The state of patching."
   "stop-on-failure (Optional)", "plain", "xsd:string", "Whether to stop patching on failure or not."
   "type (Optional)", "plain", "xsd:string", "Will be set to: ``patch``."
   "max-parallel-subclouds (Optional)", "plain", "xsd:int", "The number of subclouds to patch in parallel."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "subcloud-apply-type": "serial",
     "type": "patch",
     "stop-on-failure": "true",
     "max-parallel-subclouds": 2
   }

::

   {
     "max-parallel-subclouds": 2,
     "updated-at": None,
     "created-at": "2018-02-25T23:23:53.852473",
     "subcloud-apply-type": "serial",
     "state": "initial",
     "stop-on-failure": True,
     "type": "patch",
     "id": 2
   }

**********************************************
Deletes the patch strategy from the database
**********************************************

.. rest_method:: DELETE /v1.0/sw-update-strategy

**Normal response codes**

204

This operation does not accept a request body.

--------------------------------
Subcloud Patch Strategy Actions
--------------------------------

Subcloud patch strategy can be actioned.

****************************************
Executes an action on a patch strategy
****************************************

.. rest_method:: POST /v1.0/sw-update-strategy/actions

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "action (Optional)", "plain", "xsd:string", "Perform one of the following actions on the patch strategy: Valid values are: ``apply``, or ``abort``."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud-apply-type (Optional)", "plain", "xsd:string", "Subcloud apply type"
   "state (Optional)", "plain", "xsd:string", "The state of patching."
   "stop-on-failure (Optional)", "plain", "xsd:string", "Whether to stop patching on failure or not."
   "type (Optional)", "plain", "xsd:string", "Will be set to: ``patch``."
   "max-parallel-subclouds (Optional)", "plain", "xsd:int", "The number of subclouds to patch in parallel."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "action": "apply",
   }

::

   {
     "max-parallel-subclouds": 2,
     "updated-at": None,
     "created-at": "2018-02-25T23:23:53.852473",
     "subcloud-apply-type": "serial",
     "state": "applying",
     "stop-on-failure": True,
     "type": "patch",
     "id": 2
   }

------------------------------
Subcloud Patch Strategy Steps
------------------------------

Subcloud patch strategy steps can be retrieved.

***********************************************
Lists all patch strategy steps for all clouds
***********************************************

.. rest_method:: GET /v1.0/sw-update-strategy/steps

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "strategy-steps (Optional)", "plain", "xsd:list", "The list of patch strategy steps."
   "cloud (Optional)", "plain", "xsd:string", "The name of the cloud to which the patch strategy steps apply."
   "state (Optional)", "plain", "xsd:string", "The state of patching."
   "details (Optional)", "plain", "xsd:string", "Details about patching."
   "stage (Optional)", "plain", "xsd:int", "The stage of patching."

::

   {
     "strategy-steps": [
       {
         "updated-at": None,
         "created-at": "2018-02-25T23:23:53.852473",
         "state": "initial",
         "details": "",
         "id": 1,
         "cloud": "subcloud6",
         "stage": 1
       },
       {
         "updated-at": None,
         "created-at": "2018-02-25T23:23:53.852473",
         "state": "initial",
         "details": "",
         "id": 2,
         "cloud": "subcloud7",
         "stage": 1
       },
       {
         "updated-at": None,
         "created-at": "2018-02-25T23:23:53.852473",
         "state": "initial",
         "details": "",
         "id": 3,
         "cloud": "subcloud8",
         "stage": 1
       },
     ]
   }

This operation does not accept a request body.

******************************************************************
Shows the details of patch strategy steps for a particular cloud
******************************************************************

.. rest_method:: GET /v1.0/sw-update-strategy/steps/​{cloud_name}​

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "cloud (Optional)", "plain", "xsd:string", "The name of the cloud to which the patch strategy steps apply."
   "state (Optional)", "plain", "xsd:string", "The state of patching."
   "details (Optional)", "plain", "xsd:string", "Details about patching."
   "stage (Optional)", "plain", "xsd:int", "The stage of patching."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "updated-at": None,
     "created-at": None,
     "state": "initial",
     "details": "",
     "id": 1,
     "cloud": "subcloud6",
     "stage": 1
   }

This operation does not accept a request body.

-----------------------
Subcloud Patch Options
-----------------------

Subcloud Patch Options are configurable.

*************************
Lists all patch options
*************************

.. rest_method:: GET /v1.0/sw-update-options

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "sw-update-options (Optional)", "plain", "xsd:list", "The list of patch options."
   "name (Optional)", "plain", "xsd:string", "The name of the cloud to which the patch options apply."
   "compute-apply-type (Optional)", "plain", "xsd:string", "Compute host apply type, ``parallel`` or ``serial``"
   "subcloud-id (Optional)", "plain", "xsd:int", "The id of the cloud (will be 0 for the all clouds default)."
   "max-parallel-computes (Optional)", "plain", "xsd:int", "The number of compute hosts to patch in parallel."
   "alarm-restriction-type (Optional)", "plain", "xsd:string", "Whether to allow patching if subcloud alarms are present or not, ``strict`` or ``relaxed``."
   "storage-apply-type (Optional)", "plain", "xsd:string", "Storage host apply type, ``parallel`` or ``serial``."
   "default-instance-action (Optional)", "plain", "xsd:string", "How instances should be handled, ``stop-start`` or ``migrate``."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "sw-update-options": [
       {
         "name": "all clouds default",
         "compute-apply-type": "parallel",
         "subcloud-id": None,
         "updated-at": "2018-02-25 23:34:03.099691",
         "created-at": None,
         "alarm-restriction-type": "relaxed",
         "storage-apply-type": "parallel",
         "max-parallel-computes": 3,
         "default-instance-action": "migrate",
         "id": 1
       },
       {
         "name": "subcloud6",
         "compute-apply-type": "parallel",
         "subcloud-id": 1,
         "updated-at": "2018-02-25 23:41:42.877013",
         "created-at": "2018-02-25 19:07:20.767609",
         "alarm-restriction-type": "relaxed",
         "storage-apply-type": "parallel",
         "max-parallel-computes": 3,
         "default-instance-action": "migrate",
         "id": 1
       }
     ]
   }

This operation does not accept a request body.

***************************************************************************************************************************
Shows patch options, defaults or per subcloud. Use ``RegionOne`` as subcloud for default options which are pre-configured
***************************************************************************************************************************

.. rest_method:: GET /v1.0/sw-update-options/​{subcloud}​

**Normal response codes**

200

**Error response codes**

itemNotFound (404), badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name of the cloud to which the patch options apply."
   "compute-apply-type (Optional)", "plain", "xsd:string", "Compute host apply type, ``parallel`` or ``serial``"
   "subcloud-id (Optional)", "plain", "xsd:int", "The id of the cloud (will be 0 for the all clouds default)."
   "max-parallel-computes (Optional)", "plain", "xsd:int", "The number of compute hosts to patch in parallel."
   "alarm-restriction-type (Optional)", "plain", "xsd:string", "Whether to allow patching if subcloud alarms are present or not, ``strict`` or ``relaxed``."
   "storage-apply-type (Optional)", "plain", "xsd:string", "Storage host apply type, ``parallel`` or ``serial``."
   "default-instance-action (Optional)", "plain", "xsd:string", "How instances should be handled, ``stop-start`` or ``migrate``."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "name": "subcloud6",
     "compute-apply-type": "parallel",
     "subcloud-id": 1,
     "updated-at": "2018-02-25 23:41:42.877013",
     "created-at": "2018-02-25 19:07:20.767609",
     "alarm-restriction-type": "relaxed",
     "storage-apply-type": "parallel",
     "max-parallel-computes": 3,
     "default-instance-action": "migrate",
     "id": 1
   }

This operation does not accept a request body.

****************************************************************************************************
Updates patch options, defaults or per subcloud. Use ``RegionOne`` as subcloud for default options
****************************************************************************************************

.. rest_method:: POST /v1.0/sw-update-options/​{subcloud}​

-  storage-apply-type,

-  compute-apply-type,

-  max-parallel-computes,

-  alarm-restriction-type,

-  default-instance-action,

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."
   "storage-apply-type (Optional)", "plain", "xsd:string", "Storage host apply type, ``parallel`` or ``serial``."
   "compute-apply-type (Optional)", "plain", "xsd:string", "Compute host apply type, ``parallel`` or ``serial``."
   "max-parallel-computes (Optional)", "plain", "xsd:string", "The number of compute hosts to patch in parallel."
   "alarm-restriction-type (Optional)", "plain", "xsd:string", "Whether to allow patching if subcloud alarms are present or not, ``strict`` or ``relaxed``."
   "default-instance-action (Optional)", "plain", "xsd:string", "How instances should be handled, ``stop-start`` or ``migrate``."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name of the cloud to which the patch options apply."
   "compute-apply-type (Optional)", "plain", "xsd:string", "Compute host apply type, ``parallel`` or ``serial``"
   "subcloud-id (Optional)", "plain", "xsd:int", "The id of the cloud (will be 0 for the all clouds default)."
   "max-parallel-computes (Optional)", "plain", "xsd:int", "The number of compute hosts to patch in parallel."
   "alarm-restriction-type (Optional)", "plain", "xsd:string", "Whether to allow patching if subcloud alarms are present or not, ``strict`` or ``relaxed``."
   "storage-apply-type (Optional)", "plain", "xsd:string", "Storage host apply type, ``parallel`` or ``serial``."
   "default-instance-action (Optional)", "plain", "xsd:string", "How instances should be handled, ``stop-start`` or ``migrate``."
   "id (Optional)", "plain", "xsd:int", "The unique identifier for this object."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "max-parallel-computes": 3,
     "default-instance-action": "migrate",
     "alarm-restriction-type": "relaxed",
     "storage-apply-type": "parallel",
     "compute-apply-type": "parallel"
   }

::

   {
     "name": "all clouds default",
     "compute-apply-type": "parallel",
     "subcloud-id": None,
     "updated-at": "2018-02-25 23:34:03.099691",
     "created-at": None,
     "alarm-restriction-type": "relaxed",
     "storage-apply-type": "parallel",
     "max-parallel-computes": 3,
     "default-instance-action": "migrate",
     "id": 1
   }

***********************************
Delete per subcloud patch options
***********************************

.. rest_method:: DELETE /v1.0/sw-update-options/​{subcloud}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud", "URI", "xsd:string", "The subcloud reference, name or id."

This operation does not accept a request body.

----------------
Subcloud Deploy
----------------

These APIs allow for the display and upload of the deployment manager common
files which include deploy playbook, deploy overrides, and deploy helm charts.


**************************
Show Subcloud Deploy Files
**************************

.. rest_method:: GET /v1.0/subcloud-deploy


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "subcloud_deploy", "plain", "xsd:dict", "The dictionary of subcloud deploy files."
   "deploy_chart", "plain", "xsd:string", "The file name of the deployment manager helm charts."
   "deploy_playbook", "plain", "xsd:string", "The file name of the deployment manager playbook."
   "deploy_overrides", "plain", "xsd:string", "The file name of the deployment manager overrides."

::

   {
     "subcloud_deploy":
       {
         "deploy_chart": "deployment-manager.tgz",
         "deploy_playbook": "deployment-manager-playbook.yaml",
         "deploy_overrides": "deployment-manager-overrides-subcloud.yaml"
       }
   }

This operation does not accept a request body.

****************************
Upload Subcloud Deploy Files
****************************

.. rest_method:: POST /v1.0/subcloud-deploy

Accepts Content-Type multipart/form-data.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "deploy_chart", "plain", "xsd:string", "The content of a file containing the deployment manager helm charts."
   "deploy_playbook", "plain", "xsd:string", "The content of a file containing the deployment manager playbook."
   "deploy_overrides", "plain", "xsd:string", "The content of a file containing the deployment manager overrides."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "deploy_chart", "plain", "xsd:string", "The file name of the deployment manager helm charts."
   "deploy_playbook", "plain", "xsd:string", "The file name of the deployment manager playbook."
   "deploy_overrides", "plain", "xsd:string", "The file name of the deployment manager overrides."

::

   {
     "deploy_chart": "deployment-manager.tgz",
     "deploy_playbook": "deployment-manager-playbook.yaml",
     "deploy_overrides": "deployment-manager-overrides-subcloud.yaml"
   }
