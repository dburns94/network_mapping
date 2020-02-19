#!/usr/bin/python3.6

import re
import networking as n

#intf_pattern = re.compile(r"^interface[ ]+(?P<interface>[\w/\-.]+)", re.M)
desc_pattern = re.compile(r"^[ ]+description (?P<description>.*)", re.M)
switchport_pattern = re.compile(r"^[ ]+switchport mode (?P<mode>\w+)", re.M)
vlan_pattern = re.compile(r"^[ ]+switchport \w+( allo\w+)? vlan (?P<vlan>[\d,]+)", re.M)
def get_interfaces(device):
    #print(device.config)
    interfaces = []
    # get interface sections
    matches = re.finditer(r"^interface[ ]+(?P<interface>[\w/\-.]+)[ ]*\n"+
                          r"([ ]+.+\n)*", device.config, re.M)
    for match in matches:
        # initialize data
        interface = {'name': match.group('interface'), 'description': None, 'switchport': None, 'vlan': None}
        # get description
        desc_match = desc_pattern.search(match.group(0))
        if desc_match is not None:
            interface['description'] = desc_match.group('description').strip()
        # get switchport mode
        switchport_match = switchport_pattern.search(match.group(0))
        if switchport_match is not None:
            interface['switchport'] = switchport_match.group('mode')
        # if switchport mode was found
        if interface['switchport'] is not None:
            # get vlans
            vlan_match = vlan_pattern.search(match.group(0))
            if vlan_match is not None:
                interface['vlan'] = vlan_match.group('vlan')
            elif interface['switchport'] == 'trunk':
                interface['vlan'] = 'all'
        # add data to final list
        interfaces.append(interface)
#        print(interface)
 #       print(match.group(0))
    # get interface states
#    cmd = "show interface status"
 #   device.get_response(cmd)
  #  print(device.response)
    return interfaces

def get_ips(device):
    ipv4 = []
    ipv6 = []
    # get IP interfaces
    matches = re.finditer(r"^interface[ ]+(?P<interface>[\w/\-.]+([ ]+[\w/\-.]+)?)\n"+
                          r"( .+\n)+", device.config, re.M)
    for match in matches:
        # get the interface name
        interface = match.group('interface')
        # get IPv4 addresses
        ip_matches = re.finditer(r"^[ ]+ip(v4)? address (?P<ip>(\d{1,3}\.){3}\d{1,3}(/)?(?P<prefix>\d{1,2})?)( (?P<netmask>(\d{1,3}\.){3}\d{1,3}))?", match.group(0), re.M)
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
        ip_matches = re.finditer(r"^[ ]+ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv6 data to address list
                ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'offset': ip.offset})
    # get IPv6 link-local addresses
    cmds = [
        "show ipv6 interface | include protocol|link-local",
        "show ipv6 vrf all interface | utility egrep 'protocol|link-local'"
    ]
#        "show ipv6 interface | utility egrep 'protocol|link-local'"
    device.get_response(cmds)
    matches = re.finditer(r"^(?P<interface>[\w/\-.]+([ ]+[\w/\-.]+)?)[ ]+is.*\n"+
                          r"([ ]+.*\n)*"+
                          r"[ ]+IPv6 is enabled, link-local address is (?P<ip>[\da-fA-F:]+(/\d{1,3})?)", device.response, re.M)
    for match in matches:
        # get the interface name
        interface = match.group('interface')
        # get the IP address
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # add IPv6 data to address list
            ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'offset': ip.offset})
    # get IPv4 aggregate routes
    matches = re.finditer(r"^ip route (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3}) (\d{1,3}\.){3}\d{1,3} name (?P<interface>\S+)", device.config, re.M)
    for match in matches:
        # get the IP address
        ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
        # if this is a valid IP address
        if ip.valid:
            # get the interface name
            interface = match.group('interface')
            # add IPv4 data to address list
            ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.nth(1).split('/')[0], 'offset': ip.offset})
    # get IPv6 aggregate routes
    interface = 'PD'
    matches = re.finditer(r"^ipv6 route (?P<ip>[\da-fA-F:]+/\d{1,3}) [Nn]ull", device.config, re.M)
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
    ignore_macs = ['ffff.ffff.ffff']
    # get ARP entires
    cmd = "show arp"
    device.get_response(cmd)
    matches = re.finditer(r"^Internet[ ]+(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(\d+|-)[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+(?P<interface>[\w/\-.]+)", device.response, re.M)
    for match in matches:
        if match.group('mac') not in ignore_macs:
            arps.append({'interface': match.group('interface'), 'ip': match.group('ip'), 'mac': match.group('mac')})
    return arps

def get_macs(device):
    macs = []
    # get MAC address table
    cmd = "show mac address-table"
    device.get_response(cmd)
    matches = re.finditer(r"(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+(\S+[ ]+)?(-[ ]+)?(?P<interface>[\w/\-.]+)", device.response)
    for match in matches:
        macs.append({'interface': match.group('interface'), 'mac': match.group('mac')})
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
                          r"([ ]+.*\n)+"+
                          r"[ ]+(\*[ ]+)?(?P<next_hop>(\d{1,3}\.){3}\d{1,3}|directly connected)(, (.*via (?P<interface>\S+))?)?", device.response, re.M)
        if match is not None:
            route['network'] = match.group('network')
            route['next_hop'] = match.group('next_hop').lower()
            route['process'] = match.group('process')
            if route['process'] == 'connected':
                route['next_hop'] = None
            if match.group('interface') is not None:
                route['interface'] = match.group('interface')
            # if this is a child route
            else:
                # rerun to find the ultimate route
                childHop = route['next_hop']
                network = route['network']
                process = route['process']
                route = get_route(device, n.IP(route['next_hop']))
                # replace network with previous entry
                route['network'] = network
                route['process'] = process
                # remember child route
                route['child_hop'] = childHop
                if route['process'] != 'connected':
                    route['next_hop'] = childHop
        # if the device has no route
        elif re.search(r"(Subnet|Network)[ ]+not[ ]+in[ ]+table", device.response) is not None:
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
                          r"[ ]+(?P<next_hop>[\da-fA-F:]+|directly connected|receive)((,)?( via)? (?P<interface>\S+))?", device.response, re.M)
        if match is not None:
            route['network'] = match.group('network')
            route['next_hop'] = match.group('next_hop').lower()
            route['process'] = match.group('process')
            if route['process'] == 'connected':
                route['next_hop'] = None
            if match.group('interface') is not None:
                route['interface'] = match.group('interface')
            # if this is a child route
            else:
                # rerun to find the ultimate route
                childHop = route['next_hop']
                network = route['network']
                process = route['process']
                route = get_route(device, n.IP(route['next_hop']))
                # replace network with previous entry
                route['network'] = network
                route['process'] = process
                # remember child route
                route['child_hop'] = childHop
    return route

