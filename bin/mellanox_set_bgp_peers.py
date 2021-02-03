#!/usr/bin/env python3

# To enable json api on switch:
# switch (config) # json-gw enable

# https://community.mellanox.com/s/article/getting-started-with-json-api-for-mellanox-switches
# JSON LOGIN:  https://docs.mellanox.com/display/ONYXv382110/Network+Management+Interfaces


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

Example: ./mellanox_set_bgp_peers.py 10.252.0.2 10.252.0.3 /var/www/ephemeral/prep/redbull/networks
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

url = 'fhttps://{ips}/rest/v10.04/system/'

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

#get switch IPs
# for i in range(len(NMN['subnets'][0]['ip_reservations'])):
#     switches = NMN['subnets'][0]['ip_reservations'][i]['name']
#     if 'spine' in switches:
#             ips = (NMN['subnets'][0]['ip_reservations'][i]['ip_address'])
#             switch_ips.append(ips)
print('switch ips' ,' '.join(switch_ips))
print('===============================================')


login_body = {"username": "admin", "password": password } # JSON object

for spine in switch_ips:
    login_url = "https://{}/admin/launch?script=rh&template=json-request&action=json-login".format(spine)

    session = requests.session()
#create a session and get the session ID cookie
    response = session.post(url = login_url, json = login_body, verify = False) # Do not verify self-signed certs
    response.raise_for_status() # Throw an exception if HTTP response is not 200

    response_body = json.loads(response.text) # Convert JSON to python object
    if not response.text or \
        'status' not in response_body or \
        response_body['status'] != 'OK':
        print('Error {}'.format(response.text))
        sys.exit()

    # If the above passes then we're logged in and session cookie is available
    # NOTE:  technically the session cookie is still in our open requests session!
    session_tuple = ()
    for item in  session.cookies.items():
        if 'session' in item:
            session_tuple = item

    if not session_tuple:
        print('Error no session ID returned or found')
        sys.exit()

    #default url to post commands
    action = '/admin/launch?script=rh&template=json-request&action=json-login'


#get route-map configuration
    cmd = {"cmd": 'show route-map'}
    response = session.post(url = login_url + action, json = cmd, verify = False)

#create command to delete previous route-map configuration.
    switch_response = json.loads(response.text)
    cmd_no_route_map_list=['no router bgp 65533'] #add a command to delete bgp config at the beginning of the list
    for i in range(len(switch_response['data'])):
        route_map = str(switch_response['data'][i])
        route_map = (" ".join(route_map.split()[0:2]))
        route_map = route_map[2:-1]
        cmd_no_route_map = 'no {}'.format(route_map)
        if cmd_no_route_map not in cmd_no_route_map_list:
            cmd_no_route_map_list.append(cmd_no_route_map)
    print(cmd_no_route_map_list)

    #posts NO route maps to the switch
    cmd = {"commands": cmd_no_route_map_list}
    response = session.post(url = login_url + action, json = cmd, verify = False)
    post_cmd_url = login_url + action
    switch_response = json.loads(response.text)
    pprint.pprint(switch_response)


#create command to delete previous prefix list configuraiton.
#these are hard coded, the API does not return prefix lists when called...
    #delete prefix lists
    get_prefix_list = ['no ip prefix-list pl-can', 'no ip prefix-list pl-hmn', 'no ip prefix-list pl-nmn']
    cmd = {"commands": get_prefix_list}
    response = session.post(url = login_url + action, json = cmd, verify = False)
    switch_response = json.loads(response.text)
    pprint.pprint(switch_response)
    

#define the switch prefix list commands
    cmd_prefix_list_nmn = "ip prefix-list pl-nmn seq 10 permit {} /24 ge 24".format(NMN_prefix[:-3])
    cmd_prefix_list_hmn = "ip prefix-list pl-hmn seq 20 permit {} /24 ge 24".format(HMN_prefix[:-3])
    cmd_prefix_list_can = "ip prefix-list pl-can seq 30 permit {} /24 ge 24".format(CAN_prefix[:-3])


    cmd_list = [cmd_prefix_list_can, cmd_prefix_list_hmn, cmd_prefix_list_nmn]

    #create route_map commands
    for name in ncn_names:
        for name, ip in zip(ncn_names, ncn_nmn_ips):
            route_map_nmn = "route-map {} permit 10 match ip address pl-nmn".format(name)
            cmd_list.append(route_map_nmn)
            route_map_nmn_ip = "route-map {} permit 10 set ip next-hop {}".format(name, ip)
            cmd_list.append(route_map_nmn_ip)

        for name, ip in zip(ncn_names, ncn_hmn_ips):        
            route_map_hmn = "route-map {} permit 20 match ip address pl-hmn".format(name)
            cmd_list.append(route_map_hmn)
            route_map_hmn_ip = "route-map {} permit 20 set ip next-hop {}".format(name, ip)
            cmd_list.append(route_map_hmn_ip)

        for name, ip in zip(ncn_names, ncn_can_ips):
            route_map_can = "route-map {} permit 30 match ip address pl-can".format(name) 
            cmd_list.append(route_map_can)
            route_map_can_ip = "route-map {} permit 30 set ip next-hop {}".format(name, ip)
            cmd_list.append(route_map_can_ip)

    #BGP commands
    cmd_create_bgp = 'router bgp 65533 vrf default'
    cmd_list.append(cmd_create_bgp)
    cmd_bgp_routerid = 'router-id {} force'.format(spine)
    cmd_list.append(cmd_bgp_routerid)

    for ip, name in zip(ncn_nmn_ips, ncn_names):
        cmd_bgp_neighbor = 'neighbor {} remote-as 65533'.format(ip)
        cmd_list.append(cmd_bgp_neighbor)
        cmd_bgp_route_map = 'neighbor {} route-map {}'.format(ip, name)
        cmd_list.append(cmd_bgp_route_map)

    commands = { "commands": cmd_list } 

#post all the bgp configuration commands
    response = session.post(url = login_url + action, json = commands, verify = False)
    switch_response = json.loads(response.text)
    pprint.pprint(switch_response)

    write_mem = { "cmd": "write memory" } 
    response = session.post(url = login_url + action, json = write_mem, verify = False)
    switch_response = json.loads(response.text)
    pprint.pprint(switch_response)

print('')
print('')
print('BGP configuration updated on {}, please log into the switches and verify the configuration.'.format(', '.join(switch_ips)))
print('')
print('The BGP process may need to be restarted on the switches for all of them to become ESTABLISHED.')
