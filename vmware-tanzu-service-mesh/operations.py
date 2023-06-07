""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('vmware-tanzu-service-mesh')


class VMWareTanzu(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/tsm/v1'.format(url)
        else:
            self.url = url + '/tsm/v1'
        self.verify_ssl = config.get('verify_ssl')
        self.access_token = login(config)

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            headers = {
                'Accept': 'application/json',
                'csp-auth-token': self.access_token
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params,
                                        headers=headers,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.error("{0}".format(response.status_code, ''))
                raise ConnectorError("{0}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def create_cluster(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}?createOnly=true'.format(params.pop('cluster_id'))
    params.update({
        "tags[]": [],
        "labels[]": [],
        "enableNamespaceExclusions": False,
        "namespaceExclusions[]": []
    })
    payload = check_payload(params)
    response = vm.make_rest_call(endpoint, 'PUT', data=json.dumps(payload))
    return response


def generate_security_token_for_cluster(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}/token'.format(params.pop('cluster_id'))
    response = vm.make_rest_call(endpoint, 'PUT')
    return response


def upgrade_tanzu_service_mesh_version_on_cluster(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}/apps/tsm'.format(params.pop('cluster_id'))
    payload = {
        'version': params.get('version', 'default')
    }
    response = vm.make_rest_call(endpoint, 'PUT', data=json.dumps(payload))
    return response


def get_clusters(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters'
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_cluster_details(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}'.format(params.get('cluster_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_cluster_onboard_url(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/onboard-url'
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_tanzu_service_mesh_version(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}/apps'.format(params.get('cluster_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_cluster_logs(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}/logs/{1}'.format(params.pop('cluster_id'), params.pop('type'))
    payload = check_payload(params)
    response = vm.make_rest_call(endpoint, 'GET', params=payload)
    return response


def update_cluster(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}?createOnly=false'.format(params.pop('cluster_id'))
    payload = check_payload(params)
    response = vm.make_rest_call(endpoint, 'PUT', data=json.dumps(payload))
    return response


def remove_cluster_from_tanzu_service_mesh(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}'.format(params.get('cluster_id'))
    response = vm.make_rest_call(endpoint, 'DELETE')
    return response


def uninstall_tanzu_service_mesh_from_cluster(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/clusters/{0}/apps/tmc'.format(params.get('cluster_id'))
    response = vm.make_rest_call(endpoint, 'DELETE')
    return response


def create_global_namespace(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces'
    payload = check_payload(params)
    response = vm.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
    return response


def get_global_namespaces(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces'
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_global_namespace_details(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces/{0}'.format(params.get('global_namespace_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_capabilities_enabled_for_global_namespace(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces/{0}/capabilities'.format(params.get('global_namespace_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_status_for_capability_enabled_for_global_namespace(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces/{0}/capabilities/{1}'.format(params.get('global_namespace_id'),
                                                                params.get('capability'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_member_services_in_global_namespace(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces/{0}/members'.format(params.get('global_namespace_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def update_global_namespace(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces/{0}'.format(params.pop('global_namespace_id'))
    payload = check_payload(params)
    response = vm.make_rest_call(endpoint, 'PUT', data=json.dumps(payload))
    return response


def delete_global_namespace(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/global-namespaces/{0}'.format(params.get('global_namespace_id'))
    response = vm.make_rest_call(endpoint, 'DELETE')
    return response


def get_jobs(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/jobs'
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def get_job_details(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/jobs/{0}'.format(params.get('job_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def download_job(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/jobs/{0}/download'.format(params.pop('job_id'))
    response = vm.make_rest_call(endpoint, 'GET')
    return response


def delete_job(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/jobs/{0}'.format(params.get('job_id'))
    response = vm.make_rest_call(endpoint, 'DELETE')
    return response


def get_resource_groups(config, params):
    vm = VMWareTanzu(config)
    endpoint = '/resource-groups/{0}/detailed-list'.format(params.pop('resource_group_type'))
    payload = check_payload(params)
    response = vm.make_rest_call(endpoint, 'GET', params=payload)
    return response


def login(config):
    endpoint = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"
    data = {
        'refresh_token = {0}'.format(config.get('api_key'))
    }
    response = requests.request(method='POST', url=endpoint, data=json.dumps(data), verify=config.get('verify_ssl'))
    return response.get('access_token')


def _check_health(config):
    try:
        response = get_clusters(config, params={})
        if response:
            return True
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'create_cluster': create_cluster,
    'get_clusters': get_clusters,
    'get_cluster_details': get_cluster_details,
    'get_cluster_onboard_url': get_cluster_onboard_url,
    'get_tanzu_service_mesh_version': get_tanzu_service_mesh_version,
    'get_cluster_logs': get_cluster_logs,
    'update_cluster': update_cluster,
    'remove_cluster_from_tanzu_service_mesh': remove_cluster_from_tanzu_service_mesh,
    'uninstall_tanzu_service_mesh_from_cluster': uninstall_tanzu_service_mesh_from_cluster,
    'create_global_namespace': create_global_namespace,
    'get_global_namespaces': get_global_namespaces,
    'get_global_namespace_details': get_global_namespace_details,
    'get_capabilities_enabled_for_global_namespace': get_capabilities_enabled_for_global_namespace,
    'get_status_for_capability_enabled_for_global_namespace': get_status_for_capability_enabled_for_global_namespace,
    'get_member_services_in_global_namespace': get_member_services_in_global_namespace,
    'update_global_namespace': update_global_namespace,
    'delete_global_namespace': delete_global_namespace,
    'get_jobs': get_jobs,
    'get_job_details': get_job_details,
    'download_job': download_job,
    'delete_job': delete_job,
    'get_resource_groups': get_resource_groups
}
