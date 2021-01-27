#!/usr/bin/env python3

#required commands to be run on switch prior to running this script.
# ssh server vrf default
# ssh server vrf mgmt
# https-server vrf default
# https-server vrf mgmt
# https-server rest access-mode read-write

import yaml
import requests
import urllib3
import pprint
import sys
import json
import getpass
import logging
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

usage_message = """This script updates the BGP neighbors on the management switches to match the IPs of what CSI generated.

USAGE: - <IP of switch 1> <IP of Switch 2> <Path to CSI generated network files>

       - The IPs used should be Node Management Network IPs (NMN), these IPs will be what's used for the BGP Router-ID.

       - The path must include CAN.yaml', 'HMN.yaml', 'HMNLB.yaml', 'NMNLB.yaml', 'NMN.yaml

Example: ./aruba_set_bgp_peers.py 10.252.0.2 10.252.0.3 /var/www/ephemeral/prep/redbull/networks
"""

# take in switch IP and path as arguments
try:
    switch1 = sys.argv[1]
    switch2 = sys.argv[2]
    path = os.path.join(sys.argv[3])
    if os.path.exists(path) == False:
        print('Path provided not valid')
        print('')
        print(usage_message)
        sys.exit()
except IndexError:
    print(usage_message)
    raise (SystemExit)

net_file_list = ['CAN.yaml', 'HMN.yaml', 'HMNLB.yaml', 'NMNLB.yaml', 'NMN.yaml']
net_directory =  os.listdir(path)

missing_files = []
for entry in net_file_list:
    if entry not in net_directory:
        missing_files.append(entry)

if len(missing_files) > 0:
        print('Missing {} in directory, please verify {} are all located inside the directory'.format(', '.join(missing_files), ', '.join(net_file_list)))
        sys.exit()
        
switch_ips = [switch1, switch2]

username = 'admin'
password = getpass.getpass("Switch Password: ")

def _response_ok(response, call_type):
    """
    Checks whether API HTTP response contains the associated OK code.
    :param response: Response object
    :param call_type: String containing the HTTP request type
    :return: True if response was OK, False otherwise
    """
    ok_codes = {
        "GET": [200],
        "PUT": [200, 204],
        "POST": [201, 268],
        "DELETE": [204]
    }

    return response.status_code in ok_codes[call_type]

def remote_delete(remote_url, data=None, verify=False):
    response = session.delete(remote_url)
    if not _response_ok(response, "DELETE"):
        logging.warning("FAIL")
        return False
    else:
        logging.info("SUCCESS")
        return True

def remote_get(remote_url, data=None, verify=False):
    response = session.get(remote_url)
    if not _response_ok(response, "GET"):
        logging.warning("FAIL")
        return False
    else:
        logging.info("SUCCESS")
    return response

def remote_post(remote_url, data=None):
    response = session.post(remote_url, json=data, verify=False)
    if not _response_ok(response, "POST"):
        logging.warning("FAIL")
        return False
    else:
        logging.info("SUCCESS")
    return response

def remote_put(remote_url, data=None):
    response = session.put(remote_url, json=data, verify=False)
    if not _response_ok(response, "PUT"):
        logging.warning("FAIL")
        return False
    else:
        logging.info("SUCCESS")
    return response

with open(path + '/NMN.yaml', 'r') as f:
    NMN = yaml.full_load(f)

with open(path + '/CAN.yaml', 'r') as f:
    CAN = yaml.full_load(f)

with open(path + '/HMN.yaml', 'r') as f:
    HMN = yaml.full_load(f)

with open(path + '/HMNLB.yaml', 'r') as f:
    HMNLB = yaml.full_load(f)

with open(path + '/NMNLB.yaml', 'r') as f:
    NMNLB = yaml.full_load(f)

#switch IPs
with open(path + '/HMN.yaml', 'r') as f:
    HMN = yaml.full_load(f)

CAN_prefix=(CAN['cidr'])
HMN_prefix=(HMNLB['cidr'])
NMN_prefix=(NMNLB['cidr'])

asn=65533

ncn_nmn_ips = []
ncn_names = []
ncn_can_ips = []
ncn_hmn_ips = []

all_prefix=[CAN_prefix, HMN_prefix, NMN_prefix]

#NCN hostnames
for i in range(len(NMN['subnets'][1]['ip_reservations'])):
    NCN = NMN['subnets'][1]['ip_reservations'][i]['name']
    if 'ncn-w' in NCN:
        name = (NMN['subnets'][1]['ip_reservations'][i]['name'])
        ncn_names.append(name)
print('ncn names:' ,' '.join(ncn_names))

#NMN NCN IPs
for i in range(len(NMN['subnets'][1]['ip_reservations'])):
    NCN = NMN['subnets'][1]['ip_reservations'][i]['name']
    if 'ncn-w' in NCN:
        ips = (NMN['subnets'][1]['ip_reservations'][i]['ip_address'])
        ncn_nmn_ips.append(ips)
print('ncn nmn ips:' ,' '.join(ncn_nmn_ips))

#CAN NCN IPs
for i in range(len(CAN['subnets'][2]['ip_reservations'])):
    NCN = CAN['subnets'][2]['ip_reservations'][i]['aliases']
    if any('ncn-w' in s for s in NCN):
        ips = (CAN['subnets'][2]['ip_reservations'][i]['ip_address'])
        ncn_can_ips.append(ips)
print('ncn can ips:' ,' '.join(ncn_can_ips))

#HMN NCN IPs
for i in range(len(HMN['subnets'][1]['ip_reservations'])):
    NCN = HMN['subnets'][1]['ip_reservations'][i]['name']
    if 'ncn-w' in NCN:
        ips = (HMN['subnets'][1]['ip_reservations'][i]['ip_address'])
        ncn_hmn_ips.append(ips)
print('ncn hmn ips:' ,' '.join(ncn_hmn_ips))

for i in range(len(NMN['subnets'][0]['ip_reservations'])):
    switches = NMN['subnets'][0]['ip_reservations'][i]['name']
    if 'spine' in switches:
            ips = (NMN['subnets'][0]['ip_reservations'][i]['ip_address'])
#            switch_ips.append(ips)
print('switch ips' ,' '.join(switch_ips))
print('===============================================')

#json payload
bgp_data = {
    'asn': asn,
    'router_id': ''
}

bgp_neighbor10_05 = {
	"ip_or_group_name": "",
	"remote_as": asn,
	"route_maps": {
		"ipv4-unicast": {
			"in": ""
		}
	},
	"shutdown": False,
	"activate": {
		"ipv4-unicast": True
	}
}

bgp_neighbor10_06 = {
	"ip_or_ifname_or_group_name": "",
	"remote_as": asn,
	"route_maps": {
		"ipv4-unicast": {
			"in": ""
		}
	},
	"shutdown": False,
	"activate": {
		"ipv4-unicast": True
	}
}

prefix = ['pl-can', 'pl-hmn', 'pl-nmn']

prefix_list_entry = {
  'action': 'permit',
  'ge': 24,
  'le': 0,
  'preference': 10,
  'prefix': ''
}

prefix_list = {
  'address_family': 'ipv4',
  'name': ''
}

route_map = {
  'name': ''
}

route_map_entry_nmn = {
    'action': 'permit',
    'match_ipv4_prefix_list': {
        'pl-can': '/rest/v10.04/system/prefix_lists/pl-nmn'
    },
    'preference': 10,
    'set': {
        'ipv4_next_hop_address': ''
    }
}

route_map_entry_hmn = {
    'action': 'permit',
    'match_ipv4_prefix_list': {
        'pl-hmn': '/rest/v10.04/system/prefix_lists/pl-hmn'
    },
    'preference': 20,
    'set': {
        'ipv4_next_hop_address': ''
    }
}

route_map_entry_can = {
    'action': 'permit',
    'match_ipv4_prefix_list': {
        'pl-can': '/rest/v10.04/system/prefix_lists/pl-can'
    },
    'preference': 30,
    'set': {
        'ipv4_next_hop_address': ''
    }
}

username = 'admin'
#password = 
creds = {'username': username, 'password': password}
version = 'v10.04'



session = requests.Session()

for ips in switch_ips:
    base_url = 'https://{0}/rest/{1}/'.format(ips, version)
    try:
        response = session.post(base_url + 'login', data=creds, verify=False, timeout=5)
    except requests.exceptions.ConnectTimeout:
        logging.warning('ERROR: Error connecting to host: connection attempt timed out.  Verify the switch IPs')
        exit(-1)
    # Response OK check needs to be passed "PUT" since this POST call returns 200 instead of conventional 201
    if not _response_ok(response, "PUT"):
        logging.warning("FAIL: Login failed with status code %d: %s" % (response.status_code, response.text))
        exit(-1)
    else:
        logging.info("SUCCESS: Login succeeded")

    #remove bgp config
    bgp_url = base_url + 'system/vrfs/default/bgp_routers/65533'
    response = remote_delete(bgp_url)

    #get prefix lists
    prefix_url = base_url + 'system/prefix_lists'
    response = remote_get(prefix_url)
    pre_list = response.json()

    #remove prefix lists
    for pf in pre_list:
        print('removing prefix_list: {0} from {1}'.format(pf, ips))
        response = remote_delete(prefix_url + '/' + pf)

    #remove route map config
    route_map_url = base_url + 'system/route_maps'
    response = remote_get(route_map_url)
    route_map1 = response.json()

    for rm in route_map1:
        print('removing route-map: {0} from {1}'.format(rm, ips))
        response = remote_delete(route_map_url + '/' + rm)

    #add prefix lists
    for p in prefix:
        prefix_list['name'] = p
        print('adding prefix lists to {0}'.format(ips))
        response = remote_post(prefix_url, prefix_list)
        prefix_list_entry_url = base_url + 'system/prefix_lists/{0}/prefix_list_entries'.format(p)

        if 'pl-can' in p:
            prefix_list_entry['prefix'] = CAN_prefix
            prefix_list_entry['preference'] = 10
            response = remote_post(prefix_list_entry_url, prefix_list_entry)

        if 'pl-hmn' in p:
            prefix_list_entry['prefix'] = HMN_prefix
            prefix_list_entry['preference'] = 20
            response = remote_post(prefix_list_entry_url, prefix_list_entry)            

        if 'pl-nmn' in p:
            prefix_list_entry['prefix'] = NMN_prefix
            prefix_list_entry['preference'] = 30
            response = remote_post(prefix_list_entry_url, prefix_list_entry)

    #create route maps
    for name in ncn_names:
        route_map_entry_url = base_url + 'system/route_maps/{0}/route_map_entries'.format(name)
        route_map['name'] = name
        response = remote_post(route_map_url, route_map)
        print('adding route-maps to {0}'.format(ips))

    for ncn, name in zip(ncn_can_ips, ncn_names):
        route_map_entry_can['set']['ipv4_next_hop_address'] = ncn
        route_map_can_url = base_url + 'system/route_maps/{0}/route_map_entries'.format(name)
        response = remote_post(route_map_can_url, route_map_entry_can)

    for ncn, name in zip(ncn_hmn_ips, ncn_names):
        route_map_entry_hmn['set']['ipv4_next_hop_address'] = ncn
        route_map_hmn_url = base_url + 'system/route_maps/{0}/route_map_entries'.format(name)
        response = remote_post(route_map_hmn_url, route_map_entry_hmn)

    for ncn, name in zip(ncn_nmn_ips, ncn_names):
        route_map_entry_nmn['set']['ipv4_next_hop_address'] = ncn
        route_map_nmn_url = base_url + 'system/route_maps/{0}/route_map_entries'.format(name)
        response = remote_post(route_map_nmn_url, route_map_entry_nmn)

    #add bgp asn and router id    
    bgp_data['router_id'] = ips
    bgp_router_id_url = base_url + 'system/vrfs/default/bgp_routers'
    response = remote_post(bgp_router_id_url, bgp_data)
    print('adding BGP configuration to {0}'.format(ips))

    #get switch firmware
    firmware_url = base_url + 'firmware'
    response = remote_get(firmware_url)
    firmware = response.json()

    #update BGP neighbors on firmware of 10.06
    if '10.06' in firmware['current_version']:
        for ncn, names in zip(ncn_nmn_ips, ncn_names):
            bgp_neighbor10_06['ip_or_ifname_or_group_name'] = ncn 
            bgp_neighbor_url = base_url + 'system/vrfs/default/bgp_routers/65533/bgp_neighbors'
            bgp_neighbor10_06['route_maps']['ipv4-unicast']['in'] = '/rest/v10.04/system/route_maps/' + names
            response = remote_post(bgp_neighbor_url, bgp_neighbor10_06)
        for x in switch_ips:
            if x != ips:
                vsx_neighbor = dict(bgp_neighbor10_06)
                vsx_neighbor['ip_or_ifname_or_group_name'] = x
                del vsx_neighbor['route_maps']
                response = remote_post(bgp_neighbor_url, vsx_neighbor)

    #update BGP neighbors on firmware of 10.06
    if '10.05' in firmware['current_version']:
        for ncn, names in zip(ncn_nmn_ips, ncn_names):
            bgp_neighbor10_05['ip_or_group_name'] = ncn 
            bgp_neighbor_url = base_url + 'system/vrfs/default/bgp_routers/65533/bgp_neighbors'
            bgp_neighbor10_05['route_maps']['ipv4-unicast']['in'] = '/rest/v10.04/system/route_maps/' + names
            response = remote_post(bgp_neighbor_url, bgp_neighbor10_05)
        for x in switch_ips:
            if x != ips:
                vsx_neighbor = dict(bgp_neighbor10_05)
                vsx_neighbor['ip_or_group_name'] = x
                del vsx_neighbor['route_maps']
                response = remote_post(bgp_neighbor_url, vsx_neighbor)

    write_mem_url = base_url + 'fullconfigs/startup-config?from=%2Frest%2Fv10.04%2Ffullconfigs%2Frunning-config'
    response = remote_put(write_mem_url)
    if response.status_code == 200:
        print('Configuration saved on {}'.format(ips))

    logout = session.post(f'https://{ips}/rest/v10.04/logout') #logout of switch

print('')
print('')
print('BGP configuration updated on {}, please log into the switches and verify the configuration.'.format(', '.join(switch_ips)))
print('')
print('The BGP process may need to be restarted on the switches for all of them to become ESTABLISHED.')