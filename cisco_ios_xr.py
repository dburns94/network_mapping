#!/usr/bin/python3.6

import re
import networking as n
import cisco_ios as ios

def get_interfaces(device):
    return ios.get_interfaces(device)

def get_ips(device):
    return ios.get_ips(device)

def get_arps(device):
    arps = []
    # get ARP entries
    cmd = "show arp"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(\d+|-)[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+\w+[ ]+(?P<interface>[\w/\-.]+)", device.response, re.M)
    for match in matches:
        arps.append({'interface': match.group('interface'), 'ip': match.group('ip'), 'mac': match.group('mac')})
    return arps

def get_macs(device):
    macs = []
    # get MAC entries
    arps = get_arps(device)
    for arp in arps:
        macs.append({'interface': arp['interface'], 'mac': arp['mac']})
    return macs

def get_route(device, address):
    routes = []
    route = {'network': None, 'process': None, 'next_hop': None, 'interface': None, 'child_hop': None}
    # if 'address' is not an IP class
    if not isinstance(address, n.IP):
        # create the IP class
        address = n.IP(address)
    # if this is an IPv4 network
    if address.type == 4:
        # get route
        cmd = "show route "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>(\d{1,3}\.){3}\d{1,3}/\d{1,3}).*\n"+
                          r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                          r"([ ]+.*\n)+"+
                          r"[ ]+(?P<next_hop>(\d{1,3}\.){3}\d{1,3}|directly connected), (.*via (?P<interface>\S+))?", device.response, re.M)
        if match is not None:
            route['network'] = match.group('network')
            route['next_hop'] = match.group('next_hop').lower()
            route['process'] = match.group('process')
            if route['process'] == 'local':
                route['next_hop'] = None
            elif route['process'] == 'connected':
                route['next_hop'] = address.addr
            if route['next_hop'] == "directly connected":
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
        # if the device has no route
        elif re.search(r"(Subnet|Network)[ ]+not[ ]+in[ ]+table", device.response) is not None:
            # get routes from all VRFs
            cmd = "show route vrf all "+address.addr
            device.get_response(cmd)
            # parse routes
            matches = re.finditer(r"^VRF:[ ]+(?P<vrf>\S+)(\n)+"+
                                  r"Routing entry for (?P<network>(\d{1,3}\.){3}\d{1,3}/\d{1,3}).*\n"+
                                  r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                  r"([ ]+.*\n)+"+
                                  r"[ ]+(?P<next_hop>(\d{1,3}\.){3}\d{1,3}|directly connected), (.*via (?P<interface>\S+))?", device.response, re.M)
            for match in matches:
                route['vrf'] = match.group('vrf')
                route['network'] = match.group('network')
                route['next_hop'] = match.group('next_hop').lower()
                route['process'] = match.group('process')
                if route['process'] == 'local':
                    route['next_hop'] = None
                elif route['process'] == 'connected':
                    route['next_hop'] = address.addr
                if route['next_hop'] == "directly connected":
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
                routes.append(route)
    # if this is an IPv6 network
    else:
        # get the route
        cmd = "show route ipv6 "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>\S+)\n"+
                          r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                          r"([ ]+.*\n)+?"+
                          r"[ ]+(?P<next_hop>[\da-fA-F:]+|directly connected), (.*via (?P<interface>\S+)(,)?\b)?", device.response, re.M)
        if match is not None:
            route['network'] = match.group('network')
            route['next_hop'] = match.group('next_hop').lower()
            route['process'] = match.group('process')
            if route['process'] == 'local':
                route['next_hop'] = None
            elif route['process'] == 'connected':
                route['next_hop'] = address.addr
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
        # if the device has no route
        elif re.search(r"(Subnet|Network)[ ]+not[ ]+in[ ]+table", device.response) is not None:
            # get routes from all VRFs
            cmd = "show route vrf all ipv6 "+address.addr
            device.get_response(cmd)
            # parse routes
            matches = re.finditer(r"^VRF:[ ]+(?P<vrf>\S+)(\n)+"+
                                  r"Routing entry for (?P<network>\S+)\n"+
                                  r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                  r"([ ]+.*\n)+?"+
                                  r"[ ]+(?P<next_hop>[\da-fA-F:]+|directly connected), (.*via (?P<interface>\S+)(,)?\b)?", device.response, re.M)
            for match in matches:
                route = {'network': None, 'process': None, 'next_hop': None, 'interface': None, 'child_hop': None}
                route['vrf'] = match.group('vrf')
                route['network'] = match.group('network')
                route['next_hop'] = match.group('next_hop').lower()
                route['process'] = match.group('process')
                if route['process'] == 'local':
                    route['next_hop'] = None
                elif route['process'] == 'connected':
                    route['next_hop'] = address.addr
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
                routes.append(route)
    if len(routes) > 0:
        # find most specific route
        route = {'network': None, 'process': None, 'next_hop': None, 'interface': None, 'child_hop': None}
        # for each route
        for each_route in routes:
#            print(each_route)
 #           if route['network'] is not None:
  #              print('  ', int(route['network'].split('/')[1]), int(each_route['network'].split('/')[1]))
   #         else:
    #            print('  ', None, int(each_route['network'].split('/')[1]))
            if route['network'] is None or int(route['network'].split('/')[1]) < int(each_route['network'].split('/')[1]):
                route = each_route
     #       print(' ', route)
    if route['network'] is '0.0.0.0/0':
        route = get_route(device, n.IP(route['network']))
#    print(f"Found route {route}.")
    return route

