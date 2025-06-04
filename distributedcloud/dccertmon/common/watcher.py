#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import hashlib
import json
import os
import re

from dateutil.parser import parse

from kubernetes import __version__ as K8S_MODULE_VERSION
from kubernetes import client, config, watch
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import base64
from oslo_utils import encodeutils

from dccertmon.common.keystone_objects import KeystoneSessionManager
from dccertmon.common import utils
from dccommon import consts as constants
from dccommon import exceptions
from dccommon import kubeoperator as sys_kube


K8S_MODULE_MAJOR_VERSION = int(K8S_MODULE_VERSION.split(".", maxsplit=1)[0])
KUBE_CONFIG_PATH = "/etc/kubernetes/admin.conf"
LOG = log.getLogger(__name__)

SECRET_ACTION_TYPE_ADDED = "ADDED"
SECRET_ACTION_TYPE_DELETED = "DELETED"
SECRET_ACTION_TYPE_EXISTING = "EXISTING"
SECRET_ACTION_TYPE_MODIFIED = "MODIFIED"

CONF = cfg.CONF


class MonitorContext(object):
    """Context data for watches."""

    def __init__(self):
        self.kubernetes_namespace = None
        self.ks_dc = KeystoneSessionManager("endpoint_cache")


class CertUpdateEventData(object):
    def __init__(self, event_data):
        raw_obj = event_data["raw_object"]
        metadata = raw_obj["metadata"]
        data = raw_obj["data"]
        managed_fields = metadata["managedFields"]
        self.action = event_data["type"]
        self.secret_name = metadata["name"]

        self.last_operation = ""
        self.last_operation_time = None
        if len(managed_fields) > 0:
            managed_field = managed_fields[0]
            self.last_operation = managed_field["operation"]
            self.last_operation_time = parse(managed_field["time"]).replace(tzinfo=None)

        creation_timestamp = metadata["creationTimestamp"]
        self.creation_time = parse(creation_timestamp).replace(tzinfo=None)
        self.ca_crt = None
        self.tls_crt = None
        self.tls_key = None
        try:
            self.ca_crt = (
                base64.decode_as_text(data["ca.crt"]).strip()
                if "ca.crt" in data
                else ""
            )
            self.tls_crt = (
                base64.decode_as_text(data["tls.crt"]).strip()
                if "tls.crt" in data
                else ""
            )
            self.tls_key = (
                base64.decode_as_text(data["tls.key"]).strip()
                if "tls.key" in data
                else ""
            )
        except TypeError:
            LOG.error("Invalid secret data.")
            if self.ca_crt is None:
                LOG.error(f"ca.crt = {data['ca.crt']}")
            elif self.tls_crt is None:
                LOG.error(f"tls.crt = {data['tls.crt']}")
            else:
                LOG.error(f"tls.key = {data['tls.key']}")

    def equal(self, obj):
        return (
            self.action == obj.action
            and self.secret_name == obj.secret_name
            and self.ca_crt == obj.ca_crt
            and self.tls_crt == obj.tls_crt
            and self.tls_key == obj.tls_key
            and self.creation_time == obj.creation_time
            and self.last_operation == obj.last_operation
            and self.last_operation_time == obj.last_operation_time
        )

    def __str__(self):
        return (
            f"action {self.action} ({self.secret_name})\n"
            f"hash: ca_crt: {self.hash(self.ca_crt)} "
            f"tls_crt {self.hash(self.tls_crt)} "
            f"tls_key {self.hash(self.tls_key)}\n"
            f"created at {self.creation_time} "
            f"last operation {self.last_operation} "
            f"last update at {self.last_operation_time}"
        )

    @staticmethod
    def hash(data):
        m = hashlib.md5()
        m.update(encodeutils.safe_encode(data))
        return m.hexdigest()


class CertUpdateEvent(object):
    def __init__(self, listener, event_data):
        self.listener = listener
        self.event_data = event_data
        self.number_of_reattempt = 0

    def run(self):
        try:
            self.listener.notify_changed(self.event_data)
        except Exception as e:
            LOG.exception(
                f"{self.__class__.__name__} update failed [attempt "
                f"#{self.number_of_reattempt}]: {e}, event: {self.event_data}"
            )
            self.number_of_reattempt = self.number_of_reattempt + 1
            return False
        else:
            return True

    def get_id(self):
        """Return the key id for the task.

        A task will be replaced with a newer task with the same id when it is
        in a queue (for reattempting)
        """
        return f"cert-update: {self.event_data.secret_name}"

    def failed(self):
        self.listener.action_failed(self.event_data)


class CertificateRenew(object):
    def __init__(self, context):
        self.context = context

    def certificate_is_ready(self, event_data):
        supported_actions = (
            SECRET_ACTION_TYPE_ADDED,
            SECRET_ACTION_TYPE_MODIFIED,
            SECRET_ACTION_TYPE_EXISTING,
        )
        if (
            event_data.action in supported_actions
            and event_data.ca_crt
            and event_data.tls_crt
            and event_data.tls_key
        ):
            return True
        else:
            return False

    def notify_changed(self, event_data):
        if self.check_filter(event_data):
            self.do_action(event_data)
            return True
        else:
            return False

    def check_filter(self, event_data):
        return False

    def recreate_secret(self, event_data):
        """Recreate secret

        It is a workaround, delete the secret for cert-manager to
        recreate it with new private key.
        """
        kube_op = sys_kube.KubeOperator()
        kube_op.kube_delete_secret(
            event_data.secret_name, self.context.kubernetes_namespace
        )
        LOG.info(
            f"Recreate secret {self.context.kubernetes_namespace}"
            f":{event_data.secret_name}"
        )

    def update_certificate(self, event_data):
        pass

    def do_action(self, event_data):
        LOG.info(f"{self.__class__.__name__} do_action: {event_data}")
        # here is a workaround for replacing private key when renewing certficate.
        # when secret is deleted, the cert-manager will recreate the secret with
        # new private key.
        # a normal renewing scenario is
        #      secret updated -> delete secret -> secret added -> secret updated
        # the first secret updated is triggered by the cert-manager renewing the cert
        # the operation does not include rekey. Then the secret is deleted so that a new
        # certificate is created with new key. Given the fact that cert-manager
        # creates new certificate secret reasonably quickly, we assume the secret update
        # on a recently created secret has new key. (normal scenario certificate renew
        # interval is far longer than 1 hour (in days). cert-manager typically completes
        # processing certificate signing request far less than 1 sec (in ms) when
        # process a single CSR. When DC root CA certificate is renewed, a large number
        # of CSRs are triggered to renew all intermediate CA certificates, cert-manager
        # is observed to have significant delay of processing CSRs. Setting the delay
        # threshold to 1 hour can support very large number (1000s) of concurrent CSR
        # requests with proper hardware and software configuration.
        reasonable_delay = 3600  # 1 hour
        delta = (
            event_data.last_operation_time - event_data.creation_time
        ).total_seconds()
        if (
            event_data.action == SECRET_ACTION_TYPE_MODIFIED
            and delta > reasonable_delay
        ):
            self.recreate_secret(event_data)
        else:
            self.update_certificate(event_data)

    def action_failed(self, event_data):
        """Fired when the action fails after maximum reattempts or reattempt aborts.

        The service stops, and the action could be replaced with a newer action
        with the same signature. This means action_failed is not fired while
        do_action has not succeeded.
        """
        LOG.warning(f"Operation {event_data} has failed")


class AdminEndpointRenew(CertificateRenew):
    def __init__(self, context):
        super(AdminEndpointRenew, self).__init__(context)
        self.secret_name = constants.DC_ADMIN_ENDPOINT_SECRET_NAME

    def check_filter(self, event_data):
        if self.secret_name == event_data.secret_name:
            return self.certificate_is_ready(event_data)
        else:
            return False

    def update_certificate(self, event_data):

        utils.update_admin_ep_cert(
            self.context.ks_dc,
            event_data.ca_crt,
            event_data.tls_crt,
            event_data.tls_key,
        )


class DCIntermediateCertRenew(CertificateRenew):
    def __init__(self, context, audit_subcloud, invalid_deploy_states):
        super(DCIntermediateCertRenew, self).__init__(context)
        self.invalid_deploy_states = invalid_deploy_states
        self.secret_pattern = re.compile("-adminep-ca-certificate$")
        self.audit_subcloud = audit_subcloud

    def check_filter(self, event_data):
        search_result = self.secret_pattern.search(event_data.secret_name)
        if search_result and search_result.start() > 0:
            # Ensure subcloud is in a valid deploy-status and online (watch
            # events can fire for secrets before the subcloud first comes online)
            subcloud_name = self._get_subcloud_name(event_data)
            try:
                (
                    subcloud_valid_state,
                    availability_status,
                    deploy_status,
                ) = utils.query_subcloud_online_with_deploy_state(
                    subcloud_name,
                    invalid_deploy_states=self.invalid_deploy_states,
                    ks_mgr=self.context.ks_dc,
                )
                if not subcloud_valid_state:
                    LOG.info(
                        f"{self.__class__.__name__} check_filter: subcloud "
                        f"{subcloud_name} is ignored, availability="
                        f"{availability_status}, deploy_status: {deploy_status}"
                    )
                    return False
            except Exception:
                LOG.exception(f"Failed to check subcloud availability: {subcloud_name}")
                return False
            return self.certificate_is_ready(event_data)
        else:
            return False

    def _get_subcloud_name(self, event_data):
        m = self.secret_pattern.search(event_data.secret_name)
        return event_data.secret_name[0 : m.start()]

    def update_certificate(self, event_data):
        subcloud_name = self._get_subcloud_name(event_data)
        LOG.info(f"update_certificate: subcloud {subcloud_name} {event_data}")

        ks_mgr = self.context.ks_dc
        subcloud_sysinv_url = utils.SubcloudSysinvEndpointCache.get_endpoint(
            subcloud_name, ks_mgr
        )
        utils.update_subcloud_ca_cert(
            ks_mgr,
            subcloud_name,
            subcloud_sysinv_url,
            event_data.ca_crt,
            event_data.tls_crt,
            event_data.tls_key,
        )

        self.audit_subcloud(subcloud_name)

    def action_failed(self, event_data):
        sc_name = self._get_subcloud_name(event_data)
        LOG.info(f"Attempt to update intermediate CA cert for {sc_name} has failed")

        # verify subcloud is under managed and online
        ks_mgr = self.context.ks_dc
        sc = utils.get_subcloud(ks_mgr, sc_name)
        if not sc:
            LOG.error(f"Cannot find subcloud {sc_name}" % sc_name)
        else:
            LOG.info(
                f"{sc_name} is {sc['management-state']}. "
                f"Software version {sc['software-version']}"
            )

            if sc["management-state"] == constants.MANAGEMENT_MANAGED:
                # don't do anything until subcloud managed
                for status in sc["endpoint_sync_status"]:
                    if (
                        status["endpoint_type"] == constants.ENDPOINT_TYPE_DC_CERT
                        and status["sync_status"] != constants.SYNC_STATUS_OUT_OF_SYNC
                    ):
                        LOG.info(
                            f"Updating {sc_name} intermediate CA has failed. Mark "
                            f"{sc_name} as dc-cert {constants.SYNC_STATUS_OUT_OF_SYNC}"
                        )
                        # update subcloud to dc-cert out-of-sync b/c last intermediate
                        # CA cert was not updated successfully
                        # an audit (default within 24 hours) will pick up and reattempt
                        utils.update_subcloud_status(
                            self.context.ks_dc,
                            sc_name,
                            constants.SYNC_STATUS_OUT_OF_SYNC,
                        )
                        break


class RootCARenew(CertificateRenew):
    def __init__(self, context):
        super(RootCARenew, self).__init__(context)
        self.secrets_to_recreate = []

    def notify_changed(self, event_data):
        if self.check_filter(event_data):
            self.do_action(event_data)
        else:
            return False

    def check_filter(self, event_data):
        if (
            event_data.secret_name != constants.DC_ADMIN_ROOT_CA_SECRET_NAME
            or not self.certificate_is_ready(event_data)
        ):
            return False

        # check against current root CA cert to see if it is updated
        if not os.path.isfile(constants.DC_ROOT_CA_CERT_PATH):
            return True

        with open(constants.DC_ROOT_CA_CERT_PATH, "r") as f:
            crt = f.read()

        m = hashlib.md5()
        m.update(encodeutils.safe_encode(event_data.ca_crt))
        md5sum = m.hexdigest()

        if crt.strip() != event_data.ca_crt:
            LOG.info(
                f"{self.__class__.__name__} check_filter[{event_data.secret_name}]: "
                f"root ca certificate has changed. md5sum {md5sum}"
            )
            # a root CA update, all required secrets needs to be recreated
            self.secrets_to_recreate = []
            return True
        else:
            LOG.info(
                f"{self.__class__.__name__} check_filter[{event_data.secret_name}]: "
                f"root ca certificate remains the same. md5sum {md5sum}"
            )
            return False

    def do_action(self, event_data):
        LOG.info(f"{self.__class__.__name__} do_action: {event_data}")
        if len(self.secrets_to_recreate) == 0:
            self.update_certificate(event_data)

        self.recreate_secrets()

    def action_failed(self, event_data):
        LOG.error("Updating root CA certificate has failed.")
        if len(self.secrets_to_recreate) > 0:
            LOG.error(f"{self.secrets_to_recreate} are not refreshed")
            self.secrets_to_recreate = []

    def update_certificate(self, event_data):
        # currently the root CA cert renewal does not replace private key
        # This is not ideal it is caused by a cert-manager issue.
        # The root CA cert is to be updated by when the admin endpoint
        # certification is updated
        # https://github.com/jetstack/cert-manager/issues/2978
        self.secrets_to_recreate = self.get_secrets_to_recreate()
        LOG.info(f"Secrets to be recreated {self.secrets_to_recreate}")

    @staticmethod
    def get_secrets_to_recreate():
        secret_names = list(utils.get_subcloud_secrets().values())
        secret_names.insert(0, constants.DC_ADMIN_ENDPOINT_SECRET_NAME)
        return secret_names

    def recreate_secrets(self):
        kube_op = sys_kube.KubeOperator()
        secret_list = self.secrets_to_recreate[:]
        for secret in secret_list:
            try:
                LOG.info(f"Recreate {constants.CERT_NAMESPACE_SYS_CONTROLLER}:{secret}")
                kube_op.kube_delete_secret(
                    secret, constants.CERT_NAMESPACE_SYS_CONTROLLER
                )
            except Exception as e:
                LOG.error(
                    f"Deleting secret {constants.CERT_NAMESPACE_SYS_CONTROLLER}:"
                    f"{secret}. Error {e}"
                )
            else:
                self.secrets_to_recreate.remove(secret)

        if len(self.secrets_to_recreate) > 0:
            # raise exception to keep reattempting
            raise Exception("Some secrets were not recreated successfully")


class DC_CertWatcher(object):
    def __init__(self):
        self.listeners = []
        self.namespace = None
        self.context = MonitorContext()
        self.last_resource_version = None
        self.is_check_existing_certificates = True

    def register_listener(self, listener):
        return self.listeners.append(listener)

    def _update_latest_resource_version(self, cc_api):
        """Retrieve the current resource_version for use in watch (re-)registration

        Note from the API:
        >  The ResourceVersion of the top-level list is what should
        >  be used when starting a watch to observe events occurring
        >  after that list was populated.

        This method retrieves this top-level resource version.
        """
        try:
            response = cc_api.list_namespaced_secret(self.namespace)
            self.last_resource_version = response.metadata.resource_version
            LOG.debug(
                f"{self.__class__.__name__}: update last_resource_version: "
                f"{self.last_resource_version} for namespace: {self.namespace}"
            )
        except Exception:
            self.last_resource_version = None
            LOG.exception(
                f"Failed to retrieve resource_version, namespace: {self.namespace}"
            )

    def handle_secret_event(self, event, on_success, on_error):
        """Handles an individual secret event

        Calls the appropriate CertWatcherListener to take action on that event.

        This may include installing the certificate.

        :param event: An event object wrapping a Kubernetes secret.
        :param on_success: Function to be called on successful execution.
        :param on_error: Function to be called on failed execution.
        """
        LOG.debug(
            f"{self.__class__.__name__} watch received new event: "
            f"{type(event.get('object'))}, {event}"
        )
        event_type = event.get("type")
        if not event_type:
            LOG.error(
                f"{self.__class__.__name__}: received unexpected event on watch, "
                f"restarting it: {event}"
            )

            self.last_resource_version = None
            raise exceptions.UnexpectedEvent(event=event)
        # Note: we should no longer receive event_type == 'ERROR'
        # (see client code - it now raises an ApiException):
        if event_type == "ERROR":
            # Unexpected error. Restart without resourceVersion.
            self.last_resource_version = None
            LOG.error(
                (
                    f"{self.__class__.__name__}: received unexpected "
                    f"type=ERROR event on watch, restarting it: {event}"
                )
            )
            raise exceptions.UnexpectedEvent(event=event)

        event_data = CertUpdateEventData(event)

        for listener in self.listeners:
            update_event = CertUpdateEvent(listener, event_data)

            try:
                if listener.notify_changed(event_data):
                    on_success(update_event.get_id())
            except Exception as e:
                LOG.exception(
                    f"{self.__class__.__name__}: monitor action in "
                    f"namespace={self.namespace} failed: {event_data},  {e}"
                )
                on_error(update_event)

    def _get_kubernetes_core_client(self):
        """Returns the kubernetes CoreV1Api according to k8s version."""
        config.load_kube_config(KUBE_CONFIG_PATH)
        if K8S_MODULE_MAJOR_VERSION < 12:
            c = Configuration()
        else:
            c = Configuration().get_default_copy()
        c.verify_ssl = True
        Configuration.set_default(c)
        return client.CoreV1Api()

    def start_watch(self, on_success, on_error):
        """Monitors events on secrets in the watched namespaces (CertWatcher.namespace)

        Calls handle_secret_event to process each new event.

        :param on_success: function to be called on successful execution
        :param on_error: function to be called on failed execution
        """
        ccApi = self._get_kubernetes_core_client()
        kube_watch = watch.Watch()

        # First Checks for existing certificates in the watched namespace.
        # This allows for certificates existing before dccert-mon startup
        # to get detected
        if self.is_check_existing_certificates:
            try:
                response = ccApi.list_namespaced_secret(
                    self.namespace, _preload_content=False
                )
                secrets = json.loads(response.read())
                for secret in secrets["items"]:
                    secret_event = {
                        "type": SECRET_ACTION_TYPE_EXISTING,
                        "object": secret,
                        "raw_object": secret,
                    }
                    self.handle_secret_event(secret_event, on_success, on_error)
                self.is_check_existing_certificates = False
            except Exception as e:
                LOG.exception(
                    f"{self.__class__.__name__}: Unexpected error occurred during "
                    f"the initial check for existing certificates: {e}"
                )
                raise

        kwargs = {"namespace": self.namespace}
        self._update_latest_resource_version(ccApi)
        if self.last_resource_version is not None:
            # Include resource version in call to watch. Ensures we start watch
            # from same point of expiry. Reference:
            # https://github.com/kubernetes-client/python-base/blob/
            # b4d3aad42dc23e7a6c0e5c032691f8dc385a786c/watch/watch.py#L119
            kwargs["resource_version"] = self.last_resource_version

        LOG.info(
            f"{self.__class__.__name__}: watching secrets in '{self.namespace}' "
            f"using resource version: {self.last_resource_version}"
        )

        try:
            for secret_event in kube_watch.stream(
                ccApi.list_namespaced_secret, **kwargs
            ):
                try:
                    self.handle_secret_event(secret_event, on_success, on_error)
                except exceptions.UnexpectedEvent:
                    kube_watch.stop()
                    return
        except ApiException as ex:
            if ex.status == 410:
                # Expired watch. Retrieve current resource_version for use
                # in watch re-registration, as per client API instructions
                self._update_latest_resource_version(ccApi)

                LOG.info(
                    f"{self.__class__.__name__}: watch expired in '{self.namespace}', "
                    f"restarting with resource_version: {self.last_resource_version}"
                )
            else:
                # Unexpected error. Restart without resourceVersion.
                self.last_resource_version = None
                LOG.exception(
                    f"{self.__class__.__name__}: received unexpected ApiException "
                    "on watch, restarting it"
                )
            kube_watch.stop()
            return
        except Exception as e:
            kube_watch.stop()
            LOG.exception(f"{self.__class__.__name__}: Unexpected error occurred: {e}")
            raise

    def initialize(self, audit_subcloud, invalid_deploy_states):

        self.namespace = constants.CERT_NAMESPACE_SYS_CONTROLLER
        self.context.kubernetes_namespace = constants.CERT_NAMESPACE_SYS_CONTROLLER
        self.register_listener(AdminEndpointRenew(self.context))
        self.register_listener(
            DCIntermediateCertRenew(self.context, audit_subcloud, invalid_deploy_states)
        )
        self.register_listener(RootCARenew(self.context))
