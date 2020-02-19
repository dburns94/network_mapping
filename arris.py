#!/usr/bin/python3.6

import re
import networking as n
import cisco_ios as ios

desc_pattern = re.compile(r"^[ ]+description \"?(?P<description>.*?)\"?[ ]*\n", re.M)
def get_interfaces(device):
    #print(device.config)
    interfaces = []
    matches = re.finditer(r"^interface[ ]+(?P<interface>[\w/\-.]+[ ]+[\w/\-.]+)[ ]*\n"+
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
    ipv4 = []
    ipv6 = []
    # get IPv4 addresses
    matches = re.finditer(r"^interface (?P<interface>[\w/\-.]+[ ]+[\w/\-.]+)[ ]*\n"+
                          r"([ ]+.+\n)+", device.config, re.M)
    for match in matches:
        # get the interface name
        interface = match.group('interface')
        # get IPv4 addresses
        ip_matches = re.finditer(r"^ ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}(/)?(?P<prefix>\d{1,2})?)( (?P<netmask>(\d{1,3}\.){3}\d{1,3}))?", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            if ip_match.group('prefix') is not None:
                ip = n.IP(ip_match.group('ip')+'/'+ip_match.group('prefix'))
            else:
                ip = n.IP(ip_match.group('ip'), netmask=ip_match.group('netmask'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv4 data to address list
                ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'offset': ip.offset})
        # get IPv6 addresses
        ip_matches = re.finditer(r"^ ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv6 data to address list
                ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'offset': ip.offset})
    # get IPv6 link-local addresses
    cmd = "show ipv6 interface | include VRF|^Link"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<interface>[\w/\-.]+[ ]+[\w/\-.]+),.+\n"+
                          r"Link-local address[ ]+:[ ]+(?P<ip>[\da-fA-F:]+/\d{1,3})", device.response, re.M)
    for match in matches:
        # get the link-local address
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # add IPv6 data to address list
            ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'offset': ip.offset})
    # get IPv6 aggregate routes
    interface = 'PD'
    matches = re.finditer(r"^configure ipv6 route (?P<ip>[\da-fA-F:]+/\d{1,3}) null", device.config, re.M)
    for match in matches:
        # get the network
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # add IPv6 data to address list
            ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'offset': ip.offset})
    return ipv4, ipv6

def get_arps(device):
    arps = []
    ignore_macs = ['0000.0000.0000', 'ffff.ffff.ffff']
    # get ARP entires
    cmd = "show arp"
    device.get_response(cmd)
    matches = re.finditer(r"^\d+[ ]+(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+\w+[ ]+(?P<interface>[\w\-.]+[ ]+[\w/\-.]+)", device.response, re.M)
    for match in matches:
        if match.group('mac') not in ignore_macs:
            arps.append({'interface': match.group('interface'), 'ip': match.group('ip'), 'mac': match.group('mac')})
    return arps

def get_macs(device):
    macs = []
    # get CM MACs
    cmd = "show cable modem"
    device.get_response(cmd)
    matches = re.finditer(r"^(\d+/){2}\d+-(\d+/){2}\d+[ ]+(?P<cable_mac>\d+)[ ]+.*[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+", device.response, re.M)
    for match in matches:
        macs.append({'interface': 'cable-mac '+match.group('cable_mac'), 'mac': match.group('mac')})
    # get CPE MACs
    #cmd = "show cable modem detail | include CPE\("
    cmd = "show cable modem detail | include CPE\(|PrimSID"
    device.get_response(cmd)
    matches = re.finditer(r"^(\d+/){2}\d+-(\d+/){2}\d+[ ]+CM[ ]+(?P<cm_mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+.*\n"+
                          r"(.CPE\(\w+\).*\n)+", device.response, re.M)
    for match in matches:
        cm_mac = match.group('cm_mac')
        for mac in macs:
            if mac['mac'] == cm_mac:
                mac_matches = re.finditer(r"^.CPE\(\w+\)[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+", match.group(0), re.M)
                for mac_match in mac_matches:
                    macs.append({'interface': mac['interface'], 'mac': mac_match.group('mac')})
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
        cmd = "show ip route "+address.addr+" detail"
    # if this is an IPv6 network
    else:
        if address.addr == '::':
            cmd = "show ipv6 route ::/0 detail"
        else:
            cmd = "show ipv6 route "+address.addr+" detail"
    # get the route
    device.get_response(cmd)
    match = re.search(r"[ ]+IPv(4|6) Route Dest:[ ]+(?P<network>\S+)\n"+
                      r"[ ]+Next Hop:[ ]+(?P<next_hop>\S+)\n"+
                      r"([ ]+.+\n)+"+
                      r"[ ]+Protocol:[ ]+(?P<process>\S+)( .*)?\n"+
                      r"([ ]+.+\n)+"+
                      r"[ ]+Interface:[ ]+(?P<interface>[\S ]+)", device.response)
    if match is not None:
        route['Network'] = match.group('network')
        route['Next-Hop'] = match.group('next_hop')
        route['Process'] = match.group('process')
        if route['Process'] == 'local':
            route['Next-Hop'] = address.addr
        route['Interface'] = match.group('interface')
    return route

