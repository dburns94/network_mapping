#!/usr/bin/python3.6

import re
import networking as n
import parse as p

import cisco_ios as ios

desc_pattern = re.compile(r"^[ ]+description \"?(?P<description>.*?)\"?[ ]*\n", re.M)
def get_interfaces(device):
    #print(device.config)
    interfaces = []
    matches = re.finditer(r"^interface[ ]+(?P<interface>[\w/\-]+([ ]+[\w/]+)?)[ ]*\n"+
                          r"([ ]+.+\n)*", device.config, re.M)
    for match in matches:
        # initialize data
        interface = {'name': match.group('interface'), 'description': None, 'switchport': None, 'vlan': None}
        # get description
        desc_match = desc_pattern.search(match.group(0))
        if desc_match is not None:
            interface['description'] = desc_match.group('description').strip()
        # add data to final list
        interfaces.append(interface)
    return interfaces

def get_ips(device):
    ipv4, ipv6 = ios.get_ips(device)
    for i in range(len(ipv4)):
        ipv4[i]['interface'] = p.min_spaces(ipv4[i]['interface'])
    for i in range(len(ipv6)):
        ipv6[i]['interface'] = p.min_spaces(ipv6[i]['interface'])
    return ipv4, ipv6

def get_arps(device):
    arps = []
    ignore_macs = ['0000.0000.0000', '0000.0001.0000']
    # get ARP entires
    cmd = "show arp"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<interface>[\w/\-]+([ ]+[\w/]+)?)[ ]+(\d{2}:){2}\d{2}[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+\w+[ ]+(?P<ip>(\d{1,3}\.){3}\d{1,3})", device.response, re.M)
    for match in matches:
        if match.group('mac') not in ignore_macs:
            interface = re.sub(r"CATV-MAC", r"docsis-mac", match.group('interface'))
            arps.append({'interface': interface, 'ip': match.group('ip'), 'mac': match.group('mac')})
    return arps

def get_macs(device):
    macs = []
    # if device does not have a running-config stored
    if getattr(device, 'config', None) is None:
        # get the running-config
        get_config(device)
    # get docsis-mac configs
    matches = re.finditer(r"^interface (?P<interface>docsis-mac[ ]+\d+)[ ]+\n"+
                          r"([ ]+.+\n)+", device.config, re.M)
    # for each docsis-mac
    docsis_macs = []
    ds_pattern = re.compile(r"^[ ]+downstream \d+ interface qam (?P<ds>\d+/\d+)/\d+", re.M)
    us_pattern = re.compile(r"^[ ]+upstream \d+ interface upstream (?P<us>\d+/[\d.]+)/\d+", re.M)
    for match in matches:
        docsis_mac = {'name': p.min_spaces(match.group('interface')), 'ds': [], 'us': []}
        # get all downstreams
        ds_matches = ds_pattern.finditer(match.group(0))
        for ds_match in ds_matches:
            if ds_match.group('ds') not in docsis_mac['ds']:
                docsis_mac['ds'].append(ds_match.group('ds'))
        # get all upstreams
        us_matches = us_pattern.finditer(match.group(0))
        for us_match in us_matches:
            if us_match.group('us') not in docsis_mac['us']:
                docsis_mac['us'].append(us_match.group('us'))
        # add docsis-mac to final list
        docsis_macs.append(docsis_mac)
    # get CM MACs
    cmd = "show cable modem"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(\d{1,3}\.){3}\d{1,3}[ ]+(?P<us>\d+/[\d.]+)/\S+[ ]+(?P<ds>\d+/\d+)\S+[ ]+", device.response, re.M)
    for match in matches:
        interface = None
        ds = match.group('ds')
        us = match.group('us')
        for docsis_mac in docsis_macs:
            if ds in docsis_mac['ds'] and us in docsis_mac['us']:
                macs.append({'interface': docsis_mac['name'], 'mac': match.group('mac')})
                break
    # get CPE MACs
    cmd = "show cable modem cpe"
    device.get_response(cmd)
    matches = re.finditer(r"^((\d{1,3}\.){3}\d{1,3})?[ ]+dhcp[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+((\d{1,3}\.){3}\d{1,3})?[ ]+(?P<cm_mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})", device.response, re.M)
    for match in matches:
        cm_mac = match.group('cm_mac')
        for mac in macs:
            if cm_mac == mac['mac']:
                macs.append({'interface': mac['interface'], 'mac': match.group('mac')})
                break
    return macs

def get_route(device, address):
    route = {'network': None, 'process': None, 'next_hop': None, 'interface': None, 'child_hop': None}
    # if 'address' is not an IP class
    if not isinstance(address, n.IP):
        # create the IP class
        address = n.IP(address)
    # if this is an IPv4 network
    if address.type == 4:
        # get route
        cmd = "show ip route "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>(\d{1,3}\.){3}\d{1,3}/\d{1,3}).*\n"+
                                            r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                            r"([ ]+.*\n)*"+
                                            r"[ ]+\*[ ]+(?P<next_hop>(\d{1,3}\.){3}\d{1,3}|is directly connected),( via)? (?P<interface>\S+)", device.response, re.M)
        if match is not None:
            route['network'] = match.group('network')
            route['next_hop'] = match.group('next_hop').lower()
            route['process'] = match.group('process')
            if route['process'] == 'connected':
                route['next_hop'] = address.addr
            route['interface'] = match.group('interface')
        # if the device has no route
        elif re.search(r"Network[ ]+not[ ]+in[ ]+table", device.response) is not None:
            # collect the default route
            route = get_route(device, n.IP('0.0.0.0/0'))
    # if this is an IPv6 network
    else:
        # get the route
        cmd = "show ipv6 route "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>\S+)\n"+
                                            r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                            r"([ ]+.*\n)+?"+
                                            r"[ ]+\*[ ]+(via )?(?P<next_hop>[\da-fA-F:]+|directly connected), (?P<interface>\S+)", device.response, re.M)
        if match is not None:
            route['network'] = match.group('network')
            route['next_hop'] = match.group('next_hop').lower()
            route['process'] = match.group('process')
            if route['process'] == 'connected':
                route['next_hop'] = address.addr
            route['interface'] = match.group('interface')
    return route

