__title__ = 'Microsoft Advanced Threat Protection scripted integration'
__version__ = '0.1'
__copyright__ = 'Vectra AI, Inc.'
__status__ = 'Production'

import json
import argparse
import logging.handlers
import re
from datetime import datetime, timedelta
import pickle
import os
import sys
import ssl

try:
    import urllib.request
    import urllib.parse
    import requests
    import validators
    import vat.vectra as vectra
    from jose import jwt
    from .config import COGNITO_BRAIN, COGNITO_TOKEN, TENANT_ID, APP_ID, APP_SECRET
except Exception as error:
    print("\nMissing import requirements: %s\n" % str(error))


# Setup Vectra client
VC = vectra.VectraClient(COGNITO_BRAIN, token=COGNITO_TOKEN)

# Suppress Detect certificate warning
requests.packages.urllib3.disable_warnings()
ssl._create_default_https_context = ssl._create_unverified_context

# Setup logging
LOG = logging.getLogger(__name__)


def validate_config(func):
    def config_validator():
        if bool(validators.url(COGNITO_BRAIN)):
            return func()
        else:
            raise Exception('Ensure config.py has valid ATP and Vectra config sections located in the following '
                            'directory:\n{}'.format(os.path.dirname(__file__)))

    return config_validator


def query_atp(url, method, body=None, header_update=None):
    # Returns the response body from the ATP query
    # Establish session and import token

    atp_url = 'https://api.securitycenter.windows.com/api/'

    session = requests.session()

    session.headers.update({'Authorization': 'Bearer ' + get_token()})

    if header_update is not None:
        session.headers.update(header_update)

    if method == 'POST':
        #  LOG.debug('POST headers:{}'.format(session.headers))
        LOG.debug('POST body:{}'.format(body))
        api_response = session.request(method=method, url=atp_url + url, data=body)

    else:
        api_response = session.request(method, atp_url + url)

    if api_response.status_code == 200:
        LOG.debug('Received valid response to URL:{}'.format(atp_url + url))
        valid_response = json.loads(api_response.content)

        return valid_response

    elif api_response.status_code == 201:
        LOG.debug('Received valid response to URL:{}'.format(atp_url + url))
        valid_response = json.loads(api_response.content)

        return valid_response

    elif api_response == 400:
        LOG.info('MS ATP Error results:{}'.format(json.loads(api_response.content)))

    else:
        LOG.debug('Error results:{}'.format(json.loads(api_response.content)))
        LOG.info('Possible MS ATP authentication error/un-handled condition.')


def query_sensor_by_ip(host):
    # Passed a list [IP,timestamp].  Returns a sensor dictionary
    # url = "machines/findbyip(ip='192.168.18.41',timestamp=2020-02-07T01:32:05Z)"

    url = "machines/findbyip(ip='{}',timestamp={})".format(host[0], host[1])

    LOG.debug('query_sensor_by_ip URL:{}'.format(url))

    results_list = query_atp(url, 'GET')

    return results_list


def gen_sensor_tags(sensor_dict, hostid):
    # Returns a list of tags from ATP context including any previous block/unblock action tags
    # Pull host's tags
    host_tags = VC.get_host_tags(host_id=hostid).json()['tags']

    LOG.debug('Host tags:{}'.format(host_tags))
    LOG.debug('sensor_dict:{}'.format(sensor_dict))
    tag_list = [t for t in host_tags if re.search('^Manual\s[un]*block:.*', t)]
    LOG.debug('tag_list pre ATP:{}'.format(tag_list))
    # Define ATP attributes interested in
    sensor_attrib = ['computerDnsName', 'osPlatform', 'healthStatus', 'riskScore', 'exposureLevel', 'id']
    if len(sensor_dict):

        if len(sensor_dict['value']) == 0:
            LOG.debug('Length sensor_dict = 0')
            tag_list.append('ATP_NoAgent_Or_SensorInactive')

        elif len(sensor_dict['value']) == 1:
            LOG.debug('Length of sensor_dict = 1')
            for item in sensor_attrib:
                tag_list.append('{it}: {val}'.format(it=item, val=sensor_dict['value'][0][item]))
        else:
            # find most viable sensor candidate
            sensor_list = sensor_dict['value']
            LOG.debug('Length of sensor_list:{}'.format(len(sensor_list)))

            '''index = next((i for i, x in enumerate(sensor_list) if x['status'] == 'Online'), None)
            if index:
                for item in sensor_attrib:
                    tag_list.append('{it}: {val}'.format(it=item, val=sensor_list[index][item]))
            
            else:
            '''
            tag_list.append('ATP_MultipleSensors_SameIP')

    else:
        tag_list.append('ATP_NoAgent')

    return tag_list


def get_atp_machine_id(host):
    sensor_dict = query_sensor_by_ip(host)
    if len(sensor_dict['value']) == 0:
        LOG.debug('No valid host returned.')
        return None
    elif len(sensor_dict['value']) > 1:
        LOG.debug('Multiple hosts returned, skipping.')
        return None
    else:
        LOG.debug('Valid host id returned:{}'.format(sensor_dict['value'][0]['id']))
        return sensor_dict['value'][0]['id']


def create_isolation_by_ip(host):
    # Creates an isolation rule based on IP and logs attempt
    machine_id = get_atp_machine_id(host)

    if machine_id:
        isolation = json.dumps(
                {
                    "Comment": "Machine isolated with ATP / Vectra API integration {}".format(
                        datetime.now().__format__("%Y-%m-%d %H:%M")),
                    "IsolationType": "Full"
                }
         )
        header_addition = {
            "Content-type": "application/json"
        }
        url = 'machines/{}/isolate'.format(machine_id)
        results = query_atp(url, 'POST', isolation, header_addition)
        LOG.info('Isolated machine:{}'.format(results))
        return True
    else:
        LOG.info('Unable to isolate machine:{}'.format(host))
        return False


def delete_isolation_by_ip(host):
    # Deletes isolation rule(s) based on IP and logs attempt(s)
    machine_id = get_atp_machine_id(host)

    if machine_id:
        un_isolation = json.dumps(
                {
                    "Comment": "Machine un-isolated with ATP / Vectra API integration {}".format(
                        datetime.now().__format__("%Y-%m-%d %H:%M"))
                }
         )
        header_addition = {
            "Content-type": "application/json"
        }
        url = 'machines/{}/unisolate'.format(machine_id)
        results = query_atp(url, 'POST', un_isolation, header_addition)
        LOG.info('Un-isolated machine:{}'.format(results))
        return True
    else:
        LOG.info('Unable to un-isolate machine with IP:{}'.format(ip))
        return False


def poll_vectra(tag=None, tc=None):
    #  Supplied with tag and/or threat/certainty scores, returns dict of {host_id:[IP, timestamp]}
    host_dict = {}
    '''
    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    json_response = json.loads(response.read())
    
    session = requests.session()
    session.headers.update({'Authorization': 'Token ' + COGNITO_TOKEN})

    api_response = session.request(GET, atp_url + url)
    
    if tag:
        tagged_hosts = VC.get_hosts(state='active', tags=tag).json()['results']
        LOG.debug('Results:\n{}'.format(tagged_hosts))
        for host in tagged_hosts:
            host_dict.update({host['id']: [host['last_source'], host['last_seen']]})
    if tc:
        #  t, c = args.tc.split()
        t, c = tc[0], tc[1]
        tc_hosts = VC.get_hosts(state='active', threat_gte=int(t), certainty_gte=int(c)).json()['results']
        for host in tc_hosts:
            host_dict.update({host['id']: [host['last_source'], host['last_seen']]})
        '''
    session = requests.session()
    session.headers.update({'Authorization': 'Token ' + COGNITO_TOKEN})

    if tag:
        uri = "/api/v2.1/search/hosts?page_size=100&&query_string=" \
              "host.state%3A%22active%22%20AND%20host.tags%3A%22{}%22".format(tag[0])

        tagged_hosts = session.request('GET', COGNITO_BRAIN + uri, verify=False).json()['results']

        for host in tagged_hosts:
            #  host_dict.update({host['id']: [host['last_source'], host['last_seen']]})
            host_dict.update({host['id']: [host['last_source'], host['last_detection_timestamp']]})
    if tc:
        #  t, c = args.tc.split()
        t, c = tc[0], tc[1]
        uri = "/api/v2.1/search/hosts?page_size=100&&query_string=" \
              "host.state%3A%22active%22%20AND%20host.threat%3A%3E{}%20AND%20host.certainty%3A%3E{}".format(t, c)
        tc_hosts = session.request('GET', COGNITO_BRAIN + uri, verify=False).json()['results']
        # tc_hosts = VC.get_hosts(state='active', threat_gte=int(t), certainty_gte=int(c)).json()['results']
        for host in tc_hosts:
            host_dict.update({host['id']: [host['last_source'], host['last_seen']]})
    return host_dict


def get_token():
    '''
    Todo: Handle stale token (token updated outside of script)
    '''
    def generate_token():
        url = "https://login.windows.net/{}/oauth2/token".format(TENANT_ID)
        resource_app_id_uri = "https://api.securitycenter.windows.com"

        body = {
            'resource': resource_app_id_uri,
            'client_id': APP_ID,
            'client_secret': APP_SECRET,
            'grant_type': 'client_credentials'
        }

        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(url, data)
        response = urllib.request.urlopen(req)
        json_response = json.loads(response.read())

        aad_token = json_response["access_token"]

        with open(os.path.dirname(__file__) + 'token.pickle', 'wb') as outfile:
            pickle.dump(aad_token, outfile)

        return aad_token

    #  Open saved token, return if not expired

    if os.path.exists(os.path.dirname(__file__) + 'token.pickle'):
        with open(os.path.dirname(__file__) + 'token.pickle', 'rb') as token:
            creds = pickle.load(token)

        token_exp = datetime.fromtimestamp(jwt.get_unverified_claims(creds)['exp'])

        if token_exp > (datetime.now() - timedelta(seconds=60)):
            LOG.debug('Returning existing valid token')
            return creds

        else:
            LOG.debug('Token expired, generating new token')

            return generate_token()

    else:
        LOG.debug('No token file, requesting token')
        return generate_token()


def obtain_args():
    parser = argparse.ArgumentParser(description='Poll Cognito for tagged hosts, extracts ATP contextual '
                                                 'information.  Block or unblock hosts per tags',
                                     prefix_chars='--', formatter_class=argparse.RawTextHelpFormatter,
                                     epilog='')
    parser.add_argument('--tc', type=int, nargs=2, default=False,
                        help='Poll for hosts with threat and certainty scores >=, eg --tc 50 50')
    parser.add_argument('--tag', type=str, nargs=1, default=False, help='Enrichment host tag to search for')
    parser.add_argument('--blocktag', type=str, nargs=1, default=False, help='Block hosts with this tag')
    parser.add_argument('--unblocktag', type=str, nargs=1, default=False, help='Unblock hosts with this tag')
    parser.add_argument('--verbose', default=False, action='store_true', help='Verbose logging')

    return parser.parse_args()


@validate_config
def main():
    args = obtain_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) == 1:
        print('Run atp -h for help.')
        sys.exit()

    else:
        if args.blocktag:
            hosts = poll_vectra(args.blocktag)
            for hostid in hosts.keys():
                LOG.debug('Requesting isolation for IP: {}'.format(hosts[hostid]))
                block_success = create_isolation_by_ip(hosts[hostid])
                tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)

                tag_list.append('Manual block:{}'.format(datetime.now().__format__("%Y-%m-%d %H:%M"))) \
                    if block_success else tag_list.append('Manual block failed')

                VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        if args.unblocktag:
            hosts = poll_vectra(args.unblocktag)
            for hostid in hosts.keys():
                LOG.debug('Requesting isolation rule deletion for IP: {}'.format(hosts[hostid]))
                unblock_success = delete_isolation_by_ip(hosts[hostid])
                tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)

                tag_list.append('Manual unblock:{}'.format(datetime.now().__format__("%Y-%m-%d %H:%M"))) \
                    if unblock_success else tag_list.append('Manual unblock failed')

                VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)

        # Pull hosts with tags and/or threat and certainty scores
        hosts = poll_vectra(args.tag, args.tc)

        for hostid in hosts.keys():
            LOG.info('Pulling enrichment tags for hostid:[IP,TS] {}:{}'.format(hostid, hosts[hostid]))
            tag_list = gen_sensor_tags(query_sensor_by_ip(hosts[hostid]), hostid)

            VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)


if __name__ == '__main__':
    main()
