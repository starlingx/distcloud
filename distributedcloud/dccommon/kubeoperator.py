#
# Copyright (c) 2020-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from kubernetes import __version__ as K8S_MODULE_VERSION
from kubernetes import client
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException
from kubernetes import config
from oslo_log import log as logging
from six.moves import http_client as httplib

LOG = logging.getLogger(__name__)

K8S_MODULE_MAJOR_VERSION = int(K8S_MODULE_VERSION.split('.')[0])
KUBE_CONFIG_PATH = '/etc/kubernetes/admin.conf'

CERT_MANAGER_GROUP = 'cert-manager.io'
CERT_MANAGER_VERSION = 'v1'
CERT_MANAGER_CERTIFICATE = 'certificates'


class KubeOperator(object):

    def __init__(self):
        self._kube_client_batch = None
        self._kube_client_core = None
        self._kube_client_custom_objects = None

    def _load_kube_config(self):
        config.load_kube_config(KUBE_CONFIG_PATH)
        if K8S_MODULE_MAJOR_VERSION < 12:
            c = Configuration()
        else:
            c = Configuration().get_default_copy()
        # Workaround: Turn off SSL/TLS verification
        c.verify_ssl = False
        Configuration.set_default(c)

    def _get_kubernetesclient_batch(self):
        if not self._kube_client_batch:
            self._load_kube_config()
            self._kube_client_batch = client.BatchV1Api()
        return self._kube_client_batch

    def _get_kubernetesclient_core(self):
        if not self._kube_client_core:
            self._load_kube_config()
            self._kube_client_core = client.CoreV1Api()
        return self._kube_client_core

    def _get_kubernetesclient_custom_objects(self):
        if not self._kube_client_custom_objects:
            self._load_kube_config()
            self._kube_client_custom_objects = client.CustomObjectsApi()
        return self._kube_client_custom_objects

    def kube_get_secret(self, name, namespace):
        c = self._get_kubernetesclient_core()
        try:
            return c.read_namespaced_secret(name, namespace)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Failed to get Secret %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_get_secret: %s" % e)
            raise

    def kube_delete_secret(self, name, namespace, **kwargs):
        body = {}

        if kwargs:
            body.update(kwargs)

        c = self._get_kubernetesclient_core()
        try:
            c.delete_namespaced_secret(name, namespace, body=body)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                LOG.warn("Secret %s under Namespace %s "
                         "not found." % (name, namespace))
            else:
                LOG.error("Failed to clean up Secret %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_secret: %s" % e)
            raise

    def get_cert_manager_certificate(self, namespace, name):
        custom_object_api = self._get_kubernetesclient_custom_objects()

        try:
            cert = custom_object_api.get_namespaced_custom_object(
                CERT_MANAGER_GROUP,
                CERT_MANAGER_VERSION,
                namespace,
                CERT_MANAGER_CERTIFICATE,
                name)
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return None
            else:
                LOG.error("Fail to access %s:%s. %s" % (namespace, name, e))
                raise
        else:
            return cert

    def apply_cert_manager_certificate(self, namespace, name, body):
        custom_object_api = self._get_kubernetesclient_custom_objects()

        cert = self.get_cert_manager_certificate(namespace, name)
        if cert:
            custom_object_api.patch_namespaced_custom_object(
                CERT_MANAGER_GROUP,
                CERT_MANAGER_VERSION,
                namespace,
                CERT_MANAGER_CERTIFICATE,
                name,
                body
            )
        else:
            custom_object_api.create_namespaced_custom_object(
                CERT_MANAGER_GROUP,
                CERT_MANAGER_VERSION,
                namespace,
                CERT_MANAGER_CERTIFICATE,
                body)

    def delete_cert_manager_certificate(self, namespace, name):
        custom_object_api = self._get_kubernetesclient_custom_objects()

        try:
            custom_object_api.delete_namespaced_custom_object(
                CERT_MANAGER_GROUP,
                CERT_MANAGER_VERSION,
                namespace,
                CERT_MANAGER_CERTIFICATE,
                name,
                body={}
            )
        except ApiException as e:
            if e.status != httplib.NOT_FOUND:
                LOG.error("Fail to delete %s:%s. %s" % (namespace, name, e))
                raise

    def get_pods_by_namespace(self, namespace):
        c = self._get_kubernetesclient_core()
        try:
            pods = c.list_namespaced_pod(namespace)
            return [pod.metadata.name for pod in pods.items]
        except ApiException as e:
            if e.status == httplib.NOT_FOUND:
                return []
            LOG.error("Failed to get pod name under "
                      "Namespace %s." % (namespace))
            raise
        except Exception as e:
            LOG.error("Kubernetes exception in get_pods_by_namespace: %s" % e)
            raise

    def pod_exists(self, pod, namespace):
        pods = self.get_pods_by_namespace(namespace)
        if pod in pods:
            return True
        return False

    def kube_delete_job(self, name, namespace, **kwargs):
        body = {}
        if kwargs:
            body.update(kwargs)

        b = self._get_kubernetesclient_batch()
        try:
            b.delete_namespaced_job(name, namespace, body=body)
        except ApiException as e:
            if e.status != httplib.NOT_FOUND:
                LOG.error("Failed to delete job %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_job: %s" % e)
            raise

    def kube_delete_pod(self, name, namespace, **kwargs):
        body = {}
        if kwargs:
            body.update(kwargs)

        c = self._get_kubernetesclient_core()
        try:
            c.delete_namespaced_pod(name, namespace, body=body)
        except ApiException as e:
            if e.status != httplib.NOT_FOUND:
                LOG.error("Failed to delete pod %s under "
                          "Namespace %s: %s" % (name, namespace, e.body))
                raise
        except Exception as e:
            LOG.error("Kubernetes exception in kube_delete_pod: %s" % e)
            raise
