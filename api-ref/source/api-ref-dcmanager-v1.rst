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

This operation does not accept a request body.

**Normal response codes**

200, 300

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)


Response Example
----------------

.. literalinclude:: samples/root-get-response.json
      :language: json

----------
Subclouds
----------

Subclouds are systems managed by a central System Controller.

*********************
Lists all subclouds
*********************

.. rest_method:: GET /v1.0/subclouds

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

Response
--------

.. rest_parameters:: parameters.yaml

  - subclouds: subclouds
  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subclouds/subclouds-get-response.json
      :language: json


********************
Creates a subcloud
********************

.. rest_method:: POST /v1.0/subclouds

Accepts Content-Type multipart/form-data.


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - bmc_password: bmc_password
  - bootstrap-address: bootstrap_address
  - bootstrap_values: bootstrap_values
  - deploy_config: deploy_config
  - description: subcloud_description
  - external_oam_floating_address: external_oam_floating_address
  - external_oam_gateway_address: external_oam_gateway_address
  - external_oam_subnet: external_oam_subnet
  - group_id: group_id
  - install_values: install_values
  - location: subcloud_location
  - management_gateway_address: management_gateway_ip
  - management_end_ip: management_end_ip
  - management_start_address: management_start_ip
  - management_subnet: management_subnet
  - migrate: migrate
  - secondary: secondary
  - name: subcloud_name
  - release: release
  - sysadmin_password: sysadmin_password
  - systemcontroller_gateway_address: systemcontroller_gateway_ip
  - system_mode: system_mode

Request Example
----------------

.. literalinclude:: samples/subclouds/subclouds-post-request.json
      :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - name: subcloud_name
  - description: subcloud_description
  - management-start-ip: management_start_ip
  - created-at: created_at
  - updated-at: updated_at
  - software-version: software_version
  - management-state: management_state
  - availability-status: availability_status
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - location: subcloud_location
  - group_id: group_id
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - region-name: region_name

Response Example
----------------

.. literalinclude:: samples/subclouds/subclouds-post-response.json
      :language: json


*********************************************
Shows information about a specific subcloud
*********************************************

.. rest_method:: GET /v1.0/subclouds/​{subcloud}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - peer_group_id: subcloud_peer_group_id
  - rehome_data: rehome_data
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type


Response Example
----------------

.. literalinclude:: samples/subclouds/subcloud-get-response.json
      :language: json


********************************************************
Shows additional information about a specific subcloud
********************************************************

.. rest_method:: GET /v1.0/subclouds/​{subcloud}​/detail

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - oam_floating_ip: oam_floating_ip
  - peer_group_id: subcloud_peer_group_id
  - rehome_data: rehome_data
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------
.. literalinclude:: samples/subclouds/subcloud-get-detail-response.json
      :language: json


******************************
Modifies a specific subcloud
******************************

.. rest_method:: PATCH /v1.0/subclouds/​{subcloud}​

The attributes of a subcloud which are modifiable:

-  name

-  description

-  location

-  management-state

-  group_id

-  management-subnet

-  management-gateway-ip

-  management-start-ip

-  management-end-ip

-  peer_group_id

-  bootstrap_values

-  bootstrap_address

Extra flags:

- migrate

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - management-state: subcloud_management_state
  - group_id: subcloud_group_id
  - management-subnet: subcloud_management_subnet
  - management-gateway-ip: subcloud_management_gateway_ip
  - management-start-ip: subcloud_management_start_ip
  - management-end-ip: subcloud_management_end_ip
  - peer_group_id: subcloud_peer_group_id
  - bootstrap-address: bootstrap_address
  - sysadmin-password: sysadmin_password
  - bootstrap-values: bootstrap_values_for_rehome
  - migrate: rehome_pending

Request Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - peer_group_id: subcloud_peer_group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-response.json
      :language: json


********************************
Redeploy a specific subcloud
********************************

.. rest_method:: PATCH /v1.0/subclouds/{subcloud}/redeploy

Redeploy and bootstrap a subcloud based on its previous install configurations.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - install_values: install_values
  - bootstrap_values: bootstrap_values
  - deploy_config: deploy_config
  - release: release
  - sysadmin_password: sysadmin_password
  - bmc_password: bmc_password

Request Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-redeploy-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-redeploy-response.json
      :language: json

********************************
Prestage a specific subcloud
********************************

.. rest_method:: PATCH /v1.0/subclouds/{subcloud}/prestage

Prestages a subcloud with software packages and container image archives.
The prestaged data is stored in the subcloud persistent file system
that can be used when the subcloud is reinstalled next.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - release: release
  - sysadmin_password: sysadmin_password
  - force: force

Request Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-prestage-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - prestage_software_version: prestage_software_version
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-prestage-response.json
      :language: json

*****************************************
Update the status of a specific subcloud
*****************************************

.. rest_method:: PATCH /v1.0/subclouds/{subcloud}/update_status

This is an internal API.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - endpoint: subcloud_endpoint
  - status: subcloud_endpoint_status

Request Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-update_status-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - result: subcloud_endpoint_update_result

Response Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-update_status-response.json
         :language: json

*****************************************
Migrate a specific subcloud
*****************************************

.. rest_method:: PATCH /v1.0/subclouds/{subcloud}/migrate


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - sysadmin_password: sysadmin_password

Request Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-migrate-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - rehome_data: rehome_data
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subclouds/subcloud-patch-migrate-response.json
         :language: json

*****************************
Deletes a specific subcloud
*****************************

.. rest_method:: DELETE /v1.0/subclouds/​{subcloud}​

**Normal response codes**

200

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri

This operation does not accept a request body.

----------------
Subcloud Groups
----------------

Subcloud Groups are a logical grouping managed by a central System Controller.
Subclouds in a group can be updated in parallel when applying patches or
software upgrades.

***************************
Lists all subcloud groups
***************************

.. rest_method:: GET /v1.0/subcloud-groups

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)


**Response parameters**

.. rest_parameters:: parameters.yaml

  - subcloud_groups: subcloud_groups
  - id: subcloud_group_id
  - name: subcloud_group_name
  - description: subcloud_group_description
  - max_parallel_subclouds: subcloud_group_max_parallel_subclouds
  - update_apply_type: subcloud_group_update_apply_type
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-groups/subcloud-groups-get-response.json
         :language: json


**************************
Creates a subcloud group
**************************

.. rest_method:: POST /v1.0/subcloud-groups

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - name: subcloud_group_name
  - description: subcloud_group_description
  - max_parallel_subclouds: subcloud_group_max_parallel_subclouds
  - update_apply_type: subcloud_group_update_apply_type

Request Example
----------------

.. literalinclude:: samples/subcloud-groups/subcloud-groups-post-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_group_id
  - name: subcloud_group_name
  - description: subcloud_group_description
  - max_parallel_subclouds: subcloud_group_max_parallel_subclouds
  - update_apply_type: subcloud_group_update_apply_type
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-groups/subcloud-groups-post-response.json
         :language: json


***************************************************
Shows information about a specific subcloud group
***************************************************

.. rest_method:: GET /v1.0/subcloud-groups/​{subcloud-group}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-group: subcloud_group_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_group_id
  - name: subcloud_group_name
  - description: subcloud_group_description
  - max_parallel_subclouds: subcloud_group_max_parallel_subclouds
  - update_apply_type: subcloud_group_update_apply_type
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-groups/subcloud-groups-post-response.json
         :language: json


***************************************************
Shows subclouds that are part of a subcloud group
***************************************************

.. rest_method:: GET /v1.0/subcloud-groups/​{subcloud-group}​/subclouds

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-group: subcloud_group_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - subclouds: subclouds
  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade

Response Example
----------------

.. literalinclude:: samples/subcloud-groups/subcloud-groups-get-subclouds-response.json
         :language: json


************************************
Modifies a specific subcloud group
************************************

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

.. rest_parameters:: parameters.yaml

  - subcloud-group: subcloud_group_uri
  - name: subcloud_group_name
  - description: subcloud_group_description
  - max_parallel_subclouds: subcloud_group_max_parallel_subclouds
  - update_apply_type: subcloud_group_update_apply_type

Request Example
----------------
.. literalinclude:: samples/subcloud-groups/subcloud-group-patch-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_group_id
  - name: subcloud_group_name
  - description: subcloud_group_description
  - max_parallel_subclouds: subcloud_group_max_parallel_subclouds
  - update_apply_type: subcloud_group_update_apply_type
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-groups/subcloud-group-patch-response.json
         :language: json


***********************************
Deletes a specific subcloud group
***********************************

.. rest_method:: DELETE /v1.0/subcloud-groups/​{subcloud-group}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-group: subcloud_group_uri

This operation does not accept a request body.

----------------
Subcloud Backups
----------------

Subcloud Backups allow for essential subcloud system data (and optionally container images) to be
saved and subsequently used to restore the subcloud to a previously working state.
Subcloud backups may be created, deleted or restored for a single subcloud, or for all subclouds
in a subcloud group.
Backup files may be saved locally in the subcloud or to a centralized archive in the system
controller.

************************************************************************
Generates subcloud backup files for a given subcloud or subcloud group
************************************************************************

.. rest_method:: POST /v1.0/subcloud-backup

Accepts Content-Type multipart/form-data.


**Normal response codes**

OK (200) - request has been validated and backup operation was started

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), notFound (404),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: backup_subcloud_name_or_id
  - group: backup_subcloud_group_name_or_id
  - local_only: backup_local_only
  - registry_images: backup_registry_images
  - backup_values: backup_values
  - sysadmin_password: sysadmin_password

Request Example
----------------

.. literalinclude:: samples/subcloud-backup/subcloud-create-backup-request.json
         :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - subclouds: subclouds
  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subcloud-backup/subcloud-create-backup-response.json
         :language: json

***********************************************************************************
Deletes subcloud backup files of a release for a given subcloud or subcloud group
***********************************************************************************

.. rest_method:: PATCH /v1.0/subcloud-backup/delete

Accepts Content-Type multipart/form-data.


**Normal response codes**

noContent (204) - Backup files deleted successfully

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), notFound (404),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - release: backup_delete_release
  - subcloud: backup_subcloud_name_or_id
  - group: backup_subcloud_group_name_or_id
  - local_only: backup_local_only
  - sysadmin_password: sysadmin_password

Request Example
----------------

.. literalinclude:: samples/subcloud-backup/subcloud-delete-backup-request.json
         :language: json

***********************************************************************************
Restores a subcloud or a subcloud group from a backup
***********************************************************************************

.. rest_method:: PATCH /v1.0/subcloud-backup/restore

Accepts Content-Type application/json.


**Normal response codes**

OK (200) - request has been validated and restore operation was started

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), notFound (404),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - with_install: with_install
  - release: release
  - local_only: backup_local_only
  - registry_images: backup_registry_images
  - sysadmin_password: sysadmin_password
  - subcloud: backup_subcloud_name_or_id
  - group: backup_subcloud_group_name_or_id
  - restore_values: backup_restore_values

Request Example
----------------

.. literalinclude:: samples/subcloud-backup/subcloud-restore-backup-request.json
         :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - subclouds: subclouds
  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/subcloud-backup/subcloud-restore-backup-response.json
         :language: json

----------------
Subcloud Alarms
----------------

Subcloud alarms are aggregated on the System Controller.

**************************************
Summarizes alarms from all subclouds
**************************************

.. rest_method:: GET /v1.0/alarms

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. rest_parameters:: parameters.yaml

  - alarm_summary: alarm_summary
  - uuid: alarm_summary_uuid
  - region_name: region_name
  - cloud_status: cloud_status
  - warnings: warnings
  - critical_alarms: critical_alarms
  - major_alarms: major_alarms
  - minor_alarms: minor_alarms

Response Example
----------------

.. literalinclude:: samples/alarms/alarms-get-response.json
         :language: json

------------------------
Subcloud Update Strategy
------------------------

The Subcloud update strategy is configurable.

*****************************************
Shows the details of the update strategy
*****************************************

.. rest_method:: GET /v1.0/sw-update-strategy

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - type: sw_update_strategy_type

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - type: sw_update_strategy_type
  - id: sw_update_strategy_id
  - state: sw_update_strategy_state
  - extra-args: extra_args
  - stop-on-failure: stop_on_failure
  - subcloud-apply-type: subcloud_apply_type
  - max-parallel-subclouds: max_parallel_subclouds
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-get-response.json
         :language: json

****************************
Creates the update strategy
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

.. rest_parameters:: parameters.yaml

  - cloud_name: subcloud_name
  - max-parallel-subclouds: max_parallel_subclouds
  - stop-on-failure: stop_on_failure
  - subcloud-apply-type: subcloud_apply_type
  - type: sw_update_strategy_type
  - upload-only: patch_strategy_upload_only

Request Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-post-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - type: sw_update_strategy_type
  - id: sw_update_strategy_id
  - state: sw_update_strategy_state
  - extra-args: extra_args
  - stop-on-failure: stop_on_failure
  - subcloud-apply-type: subcloud_apply_type
  - max-parallel-subclouds: max_parallel_subclouds
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-post-response.json
         :language: json


***************************
Deletes the update strategy
***************************

.. rest_method:: DELETE /v1.0/sw-update-strategy

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - type: sw_update_strategy_type

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - type: sw_update_strategy_type
  - id: sw_update_strategy_id
  - state: sw_update_strategy_state
  - extra-args: extra_args
  - stop-on-failure: stop_on_failure
  - subcloud-apply-type: subcloud_apply_type
  - max-parallel-subclouds: max_parallel_subclouds
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-delete-response.json
         :language: json

--------------------------------
Subcloud Update Strategy Actions
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

.. rest_parameters:: parameters.yaml

  - type: sw_update_strategy_type
  - action: sw_update_strategy_action

Request Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-post-action-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: sw_update_strategy_id
  - type: sw_update_strategy_type
  - state: sw_update_strategy_state
  - extra-args: extra_args
  - stop-on-failure: stop_on_failure
  - subcloud-apply-type: subcloud_apply_type
  - max-parallel-subclouds: max_parallel_subclouds
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-post-action-response.json
         :language: json

---------------------------------------
Subcloud Software Update Strategy Steps
---------------------------------------

Subcloud patch strategy steps can be retrieved.

*******************************************************
Lists all software update strategy steps for all clouds
*******************************************************

.. rest_method:: GET /v1.0/sw-update-strategy/steps

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)


**Response parameters**

.. rest_parameters:: parameters.yaml

  - strategy-steps: strategy_steps
  - id: strategy_step_id
  - cloud: subcloud_name
  - stage: strategy_step_stage
  - state: strategy_step_state
  - details: strategy_step_details
  - started-at: strategy_step_started_at
  - finished-at: strategy_step_finished_at
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-get-steps-response.json
            :language: json

******************************************************************
Shows the details of patch strategy steps for a particular cloud
******************************************************************

.. rest_method:: GET /v1.0/sw-update-strategy/steps/​{cloud_name}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - cloud_name: subcloud_name

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: strategy_step_id
  - cloud: subcloud_name
  - stage: strategy_step_stage
  - state: strategy_step_state
  - details: strategy_step_details
  - started-at: strategy_step_started_at
  - finished-at: strategy_step_finished_at
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-strategy/sw-update-strategy-get-step-subcloud-response.json
            :language: json

--------------------------------
Subcloud Software Update Options
--------------------------------

Subcloud Software Update Options are configurable.

***************************
Lists all sw-update options
***************************

.. rest_method:: GET /v1.0/sw-update-options

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Response parameters**

.. rest_parameters:: parameters.yaml

  - sw-update-options: sw_update_options
  - id: sw_update_options_id
  - name: sw_update_options_name
  - alarm-restriction-type: alarm_restriction_type
  - default-instance-action: default_instance_action
  - max-parallel-workers: max_parallel_workers
  - storage-apply-type: storage_apply_type
  - subcloud-id: subcloud_id
  - worker-apply-type: worker_apply_type
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-options/sw-update-options-get-response.json
            :language: json


******************************************************************************************************************************
Shows sw-update options (defaults or per subcloud). Use ``RegionOne`` as subcloud for default options which are pre-configured
******************************************************************************************************************************

.. rest_method:: GET /v1.0/sw-update-options/​{subcloud}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_options_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: sw_update_options_id
  - name: sw_update_options_name
  - alarm-restriction-type: alarm_restriction_type
  - default-instance-action: default_instance_action
  - max-parallel-workers: max_parallel_workers
  - storage-apply-type: storage_apply_type
  - subcloud-id: sw_update_options_subcloud_id
  - worker-apply-type: worker_apply_type
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-options/sw-update-options-get-one-response.json
            :language: json


******************************************************************************************************
Updates sw-update options, defaults or per subcloud. Use ``RegionOne`` as subcloud for default options
******************************************************************************************************

.. rest_method:: POST /v1.0/sw-update-options/​{subcloud}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_options_uri
  - alarm-restriction-type: alarm_restriction_type
  - default-instance-action: default_instance_action
  - max-parallel-workers: max_parallel_workers
  - storage-apply-type: storage_apply_type
  - worker-apply-type: worker_apply_type

Request Example
----------------

.. literalinclude:: samples/sw-update-options/sw-update-options-post-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: sw_update_options_id
  - name: sw_update_options_name
  - alarm-restriction-type: alarm_restriction_type
  - default-instance-action: default_instance_action
  - max-parallel-workers: max_parallel_workers
  - storage-apply-type: storage_apply_type
  - subcloud-id: sw_update_options_subcloud_id
  - worker-apply-type: worker_apply_type
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/sw-update-options/sw-update-options-post-response.json
            :language: json


*************************************
Delete per subcloud sw-update options
*************************************

.. rest_method:: DELETE /v1.0/sw-update-options/​{subcloud}​

This operation does not accept a request body.

**Normal response codes**

200

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_options_uri


----------------
Subcloud Deploy
----------------

These APIs allow for the display and upload of the deployment manager common
files which include deploy playbook, deploy overrides, deploy helm charts, and prestage images list.


**************************
Show Subcloud Deploy Files
**************************

.. rest_method:: GET /v1.0/subcloud-deploy/​{release}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden
(403), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - release: release_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - subcloud_deploy: subcloud_deploy
  - deploy_chart: subcloud_deploy_chart
  - deploy_playbook: subcloud_deploy_playbook
  - deploy_overrides: subcloud_deploy_overrides
  - prestage_images: subcloud_deploy_prestage_images
  - software_version: software_version

Response Example
----------------

.. literalinclude:: samples/subcloud-deploy/subcloud-deploy-get-response.json
         :language: json


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

.. rest_parameters:: parameters.yaml

  - deploy_chart: subcloud_deploy_chart_content
  - deploy_playbook: subcloud_deploy_playbook_content
  - deploy_overrides: subcloud_deploy_overrides_content
  - prestage_images: subcloud_deploy_prestage_images_content
  - release: release

Request Example
----------------

.. literalinclude:: samples/subcloud-deploy/subcloud-deploy-post-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - deploy_chart: subcloud_deploy_chart
  - deploy_playbook: subcloud_deploy_playbook
  - deploy_overrides: subcloud_deploy_overrides
  - prestage_images: subcloud_deploy_prestage_images
  - software_version: software_version

Response Example
----------------

.. literalinclude:: samples/subcloud-deploy/subcloud-deploy-post-response.json
         :language: json


************************************
Delete Subcloud Deploy Files
************************************

.. rest_method:: DELETE /v1.0/subcloud-deploy

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), notFound (404),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - release: release_uri
  - deployment_files: delete_subcloud_deployment_files
  - prestage_images: delete_subcloud_deploy_prestage_images

Request Example
----------------

.. literalinclude:: samples/subcloud-deploy/subcloud-deploy-delete-request.json
         :language: json


----------------------
Phased Subcloud Deploy
----------------------

These APIs allow for subcloud deployment to be done in phases.

******************
Creates a subcloud
******************

.. rest_method:: POST /v1.0/phased-subcloud-deploy

Accepts Content-Type multipart/form-data.


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
conflict (409), HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - bmc_password: bmc_password
  - bootstrap-address: bootstrap_address
  - bootstrap_values: bootstrap_values
  - deploy_config: deploy_config
  - description: subcloud_description
  - group_id: group_id
  - install_values: install_values
  - location: subcloud_location
  - release: release

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-post-request.json
      :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - management-state: management_state
  - availability-status: availability_status
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - error-description: error_description
  - region-name: region_name
  - management-subnet: management_subnet
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-gateway-ip: management_gateway_ip
  - openstack-installed: openstack_installed
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - data_install: data_install
  - data_upgrade: data_upgrade
  - created-at: created_at
  - updated-at: updated_at
  - group_id: group_id

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-post-response.json
      :language: json

*********************
Bootstraps a subcloud
*********************

.. rest_method:: PATCH /v1.0/phased-subcloud-deploy/bootstrap

Accepts Content-Type multipart/form-data.


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
conflict (409), HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - bootstrap-address: bootstrap_address
  - bootstrap_values: bootstrap_values
  - sysadmin_password: sysadmin_password

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-bootstrap-request.json
      :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - management-state: management_state
  - availability-status: availability_status
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - error-description: error_description
  - region-name: region_name
  - management-subnet: management_subnet
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-gateway-ip: management_gateway_ip
  - openstack-installed: openstack_installed
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - data_install: data_install
  - data_upgrade: data_upgrade
  - created-at: created_at
  - updated-at: updated_at
  - group_id: group_id

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-post-response.json
      :language: json

**********************************
Installs a subcloud
**********************************

.. rest_method:: PATCH /v1.0/phased-subcloud-deploy/{subcloud}/install

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - release: release
  - sysadmin_password: sysadmin_password
  - bmc_password: bmc_password

Accepts Content-Type multipart/form-data

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-post-install-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-post-install-response.json
      :language: json


**********************************
Configures a subcloud
**********************************

.. rest_method:: PATCH /v1.0/phased-subcloud-deploy/{subcloud}/configure

The attributes of a subcloud which are modifiable:

-  subcloud configuration (which is provided through deploy_config file)

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - deploy_config: deploy_config
  - sysadmin_password: sysadmin_password

Accepts Content-Type multipart/form-data

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-configure-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-configure-response.json
      :language: json


**********************************
Completes the subcloud deployment
**********************************

.. rest_method:: PATCH /v1.0/phased-subcloud-deploy/{subcloud}/complete

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri

Accepts Content-Type multipart/form-data

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-complete-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-continue-response.json
      :language: json


**********************************
Abort subcloud deployment
**********************************

.. rest_method:: PATCH /v1.0/phased-subcloud-deploy/{subcloud}/abort

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri

Accepts Content-Type multipart/form-data

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-abort-request.json
      :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - region-name: region_name
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade
  - endpoint_sync_status: endpoint_sync_status
  - sync_status: sync_status
  - endpoint_type: sync_status_type

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-abort-response.json
      :language: json


****************************
Resume subcloud deployment
****************************

.. rest_method:: PATCH /v1.0/phased-subcloud-deploy/{subcloud}/resume

Accepts Content-Type multipart/form-data.


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
conflict (409), HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud: subcloud_uri
  - bmc_password: bmc_password
  - bootstrap-address: bootstrap_address
  - bootstrap_values: bootstrap_values
  - deploy_config: deploy_config
  - install_values: install_values
  - release: release
  - sysadmin_password: sysadmin_password

Request Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-resume-request.json
      :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - management-state: management_state
  - availability-status: availability_status
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - error-description: error_description
  - region-name: region_name
  - management-subnet: management_subnet
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-gateway-ip: management_gateway_ip
  - openstack-installed: openstack_installed
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - data_install: data_install
  - data_upgrade: data_upgrade
  - created-at: created_at
  - updated-at: updated_at
  - group_id: group_id

Response Example
----------------

.. literalinclude:: samples/phased-subcloud-deploy/phased-subcloud-deploy-patch-resume-response.json
      :language: json

------------
System Peers
------------

System Peers are logical entities which are managed by a central System Controller.
Each System Peer maintains the information which is used for health check
and data synchronization in the protection group in Geo-Redundancy deployment.

**********************
Lists all system peers
**********************

.. rest_method:: GET /v1.0/system-peers

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

Response
--------

.. rest_parameters:: parameters.yaml

  - system_peers: system_peers
  - id: system_peer_id
  - peer-uuid: peer_uuid
  - peer-name: peer_name
  - manager-endpoint: manager_endpoint
  - manager-username: manager_username
  - peer-controller-gateway-address: peer_controller_gateway_address
  - administrative-state: administrative_state
  - heartbeat-interval: heartbeat_interval
  - heartbeat-failure-threshold: heartbeat_failure_threshold
  - heartbeat-failure-policy: heartbeat_failure_policy
  - heartbeat-maintenance-timeout: heartbeat_maintenance_timeout
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/system-peers/system-peers-get-response.json
      :language: json


*********************
Creates a system peer
*********************

.. rest_method:: POST /v1.0/system-peers

Accepts Content-Type multipart/form-data.


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - peer_uuid: peer_uuid
  - peer_name: peer_name
  - manager_endpoint: manager_endpoint
  - manager_username: manager_username
  - manager_password: manager_password
  - peer_controller_gateway_address: peer_controller_gateway_address
  - administrative_state: administrative_state
  - heartbeat_interval: heartbeat_interval
  - heartbeat_failure_threshold: heartbeat_failure_threshold
  - heartbeat_failure_policy: heartbeat_failure_policy
  - heartbeat_maintenance_timeout: heartbeat_maintenance_timeout

Request Example
----------------

.. literalinclude:: samples/system-peers/system-peers-post-request.json
      :language: json


**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: system_peer_id
  - peer-uuid: peer_uuid
  - peer-name: peer_name
  - manager-endpoint: manager_endpoint
  - manager-username: manager_username
  - peer-controller-gateway-address: peer_controller_gateway_address
  - administrative-state: administrative_state
  - heartbeat-interval: heartbeat_interval
  - heartbeat-failure-threshold: heartbeat_failure_threshold
  - heartbeat-failure-policy: heartbeat_failure_policy
  - heartbeat-maintenance-timeout: heartbeat_maintenance_timeout
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/system-peers/system-peers-post-response.json
      :language: json


**********************************************
Shows information about a specific system peer
**********************************************

.. rest_method:: GET /v1.0/system-peers/​{system-peer}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - system-peer: system_peer_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: system_peer_id
  - peer-uuid: peer_uuid
  - peer-name: peer_name
  - manager-endpoint: manager_endpoint
  - manager-username: manager_username
  - peer-controller-gateway-address: peer_controller_gateway_address
  - administrative-state: administrative_state
  - heartbeat-interval: heartbeat_interval
  - heartbeat-failure-threshold: heartbeat_failure_threshold
  - heartbeat-failure-policy: heartbeat_failure_policy
  - heartbeat-maintenance-timeout: heartbeat_maintenance_timeout
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/system-peers/system-peer-get-response.json
         :language: json


*****************************************************************
Shows subcloud peer groups that are associated with a system peer
*****************************************************************

.. rest_method:: GET /v1.0/system-peers/​{system-peer}​/subcloud-peer-groups

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - system-peer: system_peer_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - subcloud_peer_groups: subcloud_peer_groups
  - id: subcloud_peer_group_id
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/system-peers/system-peers-get-peer-groups-response.json
         :language: json


*******************************
Modifies a specific system peer
*******************************

.. rest_method:: PATCH /v1.0/system-peers/​{system-peer}​

The attributes of a subcloud group which are modifiable:

-  peer-uuid

-  peer-name

-  manager-endpoint

-  manager-username

-  manager-password

-  peer-controller-gateway-address

-  administrative-state

-  heartbeat-interval

-  heartbeat-failure-threshold

-  heartbeat-failure-policy

-  heartbeat-maintenance-timeout

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - system-peer: system_peer_uri
  - peer_uuid: peer_uuid
  - peer_name: peer_name
  - manager_endpoint: manager_endpoint
  - manager_username: manager_username
  - manager_password: manager_password
  - peer_controller_gateway_address: peer_controller_gateway_address
  - administrative_state: administrative_state
  - heartbeat_interval: heartbeat_interval
  - heartbeat_failure_threshold: heartbeat_failure_threshold
  - heartbeat_failure_policy: heartbeat_failure_policy
  - heartbeat_maintenance_timeout: heartbeat_maintenance_timeout

Request Example
----------------
.. literalinclude:: samples/system-peers/system-peer-patch-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: system_peer_id
  - peer-uuid: peer_uuid
  - peer-name: peer_name
  - manager-endpoint: manager_endpoint
  - manager-username: manager_username
  - peer-controller-gateway-address: peer_controller_gateway_address
  - administrative-state: administrative_state
  - heartbeat-interval: heartbeat_interval
  - heartbeat-failure-threshold: heartbeat_failure_threshold
  - heartbeat-failure-policy: heartbeat_failure_policy
  - heartbeat-maintenance-timeout: heartbeat_maintenance_timeout
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/system-peers/system-peer-patch-response.json
         :language: json


******************************
Deletes a specific system peer
******************************

.. rest_method:: DELETE /v1.0/system-peers/​{system-peer}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - system-peer: system_peer_uri

This operation does not accept a request body.

--------------------
Subcloud Peer Groups
--------------------

Subcloud Peer Groups are logical groupings managed by a central System Controller.
It's a group of the current managed subclouds which are supposed to be duplicated
in a peer site as secondary subclouds

******************************
Lists all subcloud peer groups
******************************

.. rest_method:: GET /v1.0/subcloud-peer-groups

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)


**Response parameters**

.. rest_parameters:: parameters.yaml

  - subcloud_peer_groups: subcloud_peer_groups
  - id: subcloud_peer_group_id
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - migration_status: subcloud_peer_group_migration_status
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-groups-get-response.json
         :language: json


*****************************
Creates a subcloud peer group
*****************************

.. rest_method:: POST /v1.0/subcloud-peer-groups

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name

Request Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-groups-post-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_peer_group_id
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - migration_status: subcloud_peer_group_migration_status
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-groups-post-response.json
         :language: json


***************************************************
Shows information about a specific subcloud group
***************************************************

.. rest_method:: GET /v1.0/subcloud-peer-groups/​{subcloud-peer-group}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-peer-group: subcloud_peer_group_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_peer_group_id
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - migration_status: subcloud_peer_group_migration_status
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-groups-post-response.json
         :language: json


******************************************************
Shows subclouds that are part of a subcloud peer group
******************************************************

.. rest_method:: GET /v1.0/subcloud-peer-groups/​{subcloud-peer-group}​/subclouds

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-peer-group: subcloud_peer_group_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - subclouds: subclouds
  - id: subcloud_id
  - group_id: group_id
  - name: subcloud_name
  - description: subcloud_description
  - location: subcloud_location
  - software-version: software_version
  - availability-status: availability_status
  - error-description: error_description
  - deploy-status: deploy_status
  - backup-status: backup_status
  - backup-datetime: backup_datetime
  - openstack-installed: openstack_installed
  - management-state: management_state
  - systemcontroller-gateway-ip: systemcontroller_gateway_ip
  - management-start-ip: management_start_ip
  - management-end-ip: management_end_ip
  - management-subnet: management_subnet
  - management-gateway-ip: management_gateway_ip
  - created-at: created_at
  - updated-at: updated_at
  - data_install: data_install
  - data_upgrade: data_upgrade

Response Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-groups-get-subclouds-response.json
         :language: json


***************************************
Modifies a specific subcloud peer group
***************************************

.. rest_method:: PATCH /v1.0/subcloud-peer-groups/​{subcloud-peer-group}​

The attributes of a subcloud peer group which are modifiable:

-  peer_group_name

-  group_priority

-  group_state

-  max_subcloud_rehoming

-  system_leader_id

-  system_leader_name

-  migration_status


**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-peer-group: subcloud_peer_group_uri
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - migration_status: subcloud_peer_group_migration_status

Request Example
----------------
.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-group-patch-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: subcloud_peer_group_id
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - migration_status: subcloud_peer_group_migration_status
  - created_at: created_at
  - updated_at: updated_at

Response Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-group-patch-response.json
         :language: json


**************************************
Migrate a specific subcloud peer group
**************************************

.. rest_method:: PATCH /v1.0/subcloud-peer-groups/​{subcloud-peer-group}​/migrate

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-peer-group: subcloud_peer_group_uri
  - sysadmin-password: sysadmin_password

Request Example
----------------
.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-groups-patch-migrate-request.json
         :language: json


**************************************
Deletes a specific subcloud peer group
**************************************

.. rest_method:: DELETE /v1.0/subcloud-peer-groups/​{subcloud-peer-group}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - subcloud-peer-group: subcloud_peer_group_uri

This operation does not accept a request body.


************************************
Audit a specific subcloud peer group
************************************

.. rest_method:: PATCH /v1.0/subcloud-peer-groups/​{subcloud-peer-group}​/audit

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - peer_uuid: peer_uuid
  - id: subcloud_peer_group_id
  - peer_group_name: subcloud_peer_group_name
  - group_priority: subcloud_peer_group_priority
  - group_state: subcloud_peer_group_administrative_state
  - max_subcloud_rehoming: subcloud_peer_group_max_subcloud_rehoming
  - system_leader_id: subcloud_peer_group_system_leader_id
  - system_leader_name: subcloud_peer_group_system_leader_name
  - migration_status: subcloud_peer_group_migration_status

Request Example
----------------
.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-group-audit-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - message: subcloud_peer_group_audit_error_message

Response Example
----------------

.. literalinclude:: samples/subcloud-peer-groups/subcloud-peer-group-audit-response.json
         :language: json


----------------------
Peer Group Association
----------------------

Peer Group Associations are logical connections managed by a central System Controller.
It's a linking of the subcloud peer group and the system peer to
establish associations with local subcloud peer groups and peer sites.

*********************************
Lists all peer group associations
*********************************

.. rest_method:: GET /v1.0/peer-group-associations

This operation does not accept a request body.

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)


**Response parameters**

.. rest_parameters:: parameters.yaml

  - peer-group-associations: peer_group_associations
  - id: peer_group_association_id
  - peer-group-id: association_peer_group_id
  - system-peer-id: system_peer_id
  - peer-group-priority: association_peer_group_priority
  - association-type: association_type
  - sync-status: association_sync_status
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/peer-group-associations/associations-get-response.json
         :language: json


********************************
Creates a peer group association
********************************

.. rest_method:: POST /v1.0/peer-group-associations

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - peer_group_id: association_peer_group_id
  - system_peer_id: system_peer_id
  - peer_group_priority: association_peer_group_priority

Request Example
----------------

.. literalinclude:: samples/peer-group-associations/associations-post-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: peer_group_association_id
  - peer-group-id: association_peer_group_id
  - system-peer-id: system_peer_id
  - peer-group-priority: association_peer_group_priority
  - association-type: association_type
  - sync-status: association_sync_status
  - sync-message: association_sync_message
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/peer-group-associations/associations-post-response.json
         :language: json


*********************************************************
Shows information about a specific peer group association
*********************************************************

.. rest_method:: GET /v1.0/peer-group-associations/​{associate_id}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - associate_id: peer_group_association_uri

This operation does not accept a request body.

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: peer_group_association_id
  - peer-group-id: association_peer_group_id
  - system-peer-id: system_peer_id
  - peer-group-priority: association_peer_group_priority
  - association-type: association_type
  - sync-status: association_sync_status
  - sync-message: association_sync_message
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/peer-group-associations/association-get-response.json
         :language: json


**********************************************
Synchronizes a specific peer group association
**********************************************

.. rest_method:: PATCH /v1.0/peer-group-associations/​{associate_id}​/sync

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - associate_id: peer_group_association_uri

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: peer_group_association_id
  - peer-group-id: association_peer_group_id
  - system-peer-id: system_peer_id
  - peer-group-priority: association_peer_group_priority
  - association-type: association_type
  - sync-status: association_sync_status
  - sync-message: association_sync_message
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/peer-group-associations/association-patch-response.json
         :language: json


******************************************
Modifies a specific peer group association
******************************************

.. rest_method:: PATCH /v1.0/peer-group-associations/​{associate_id}​

The attributes of a subcloud peer group which are modifiable:

-  peer_group_priority

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403), badMethod (405),
HTTPUnprocessableEntity (422), internalServerError (500),
serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - associate_id: peer_group_association_uri
  - peer_group_priority: association_peer_group_priority
  - sync-status: association_sync_status

Request Example
----------------
.. literalinclude:: samples/peer-group-associations/association-patch-request.json
         :language: json

**Response parameters**

.. rest_parameters:: parameters.yaml

  - id: peer_group_association_id
  - peer-group-id: association_peer_group_id
  - system-peer-id: system_peer_id
  - peer-group-priority: association_peer_group_priority
  - association-type: association_type
  - sync-status: association_sync_status
  - sync-message: association_sync_message
  - created-at: created_at
  - updated-at: updated_at

Response Example
----------------

.. literalinclude:: samples/peer-group-associations/association-patch-response.json
         :language: json


*****************************************
Deletes a specific peer group association
*****************************************

.. rest_method:: DELETE /v1.0/peer-group-associations/​{associate_id}​

**Normal response codes**

200

**Error response codes**

badRequest (400), unauthorized (401), forbidden (403),
itemNotFound (404), badMethod (405), HTTPUnprocessableEntity (422),
internalServerError (500), serviceUnavailable (503)

**Request parameters**

.. rest_parameters:: parameters.yaml

  - associate_id: peer_group_association_uri

This operation does not accept a request body.
