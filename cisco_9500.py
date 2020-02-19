#!/usr/bin/python3.6

import time

import pexpect_ext as p_ext
import parseString as ps
import networking as n

def noPaging(session, expec):
    cmd = "terminal length 0"
    p_ext.sendCMD(session, cmd, expec, 10)
    cmd = "terminal width 0"
    p_ext.sendCMD(session, cmd, expec, 10)

def getSwVersion(session, expec):
    version = ""
    cmd = "show version | include Software"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[1:-1]:
        if "Version" in line:
            line = line[line.find("Version")+8:]
            version = line[:line.find(",")]
    return version

def getSN(session, expec):
    sn = ""
    cmd = "show license udi"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[3:-2]:
        line = ps.minSpaces(line)
        sn = ps.returnN(line, 2)
    return sn

def getAllIPs(session, expec):
    ipv4 = []
    cmd = "show interfaces | include is\ up,\ line\ protocol|Internet\ address"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-2:
        if "line protocol" in lines[i]:
            if "address" in lines[i+1]:
                # get interface
                interface = lines[i].split(" ")[0]
                # get interface IPv4 address and subnet
                addressWords = ps.minSpaces(lines[i+1]).split(" ")
                subnet = addressWords[len(addressWords)-1]
                ip = subnet.split("/")[0]
                network = n.nthIPv4(subnet, 0)
                # add IPv4 data to address list
                ipv4.append({"Interface": interface, "Network": network, "Assigned": ip, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
                i += 1
        i += 1
    ipv6 = []
    cmd = "show ipv6 interface | include is\ up,\ line\ protocol|link-local\ address\ is|,\ subnet\ is"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-3:
        if "line protocol" in lines[i]:
            if "address" in lines[i+1]:
                # get interface
                interface = lines[i].split(" ")[0]
                # get link-local address
                linkLocal = ""
                linkWords = ps.minSpaces(lines[i+1]).split(" ")
                for j in range(len(linkWords)):
                    if linkWords[j] == "link-local":
                        linkLocal = linkWords[j+3].lower()
                        break
                while "subnet is" in lines[i+2]:
                    # get interface IPv6 address
                    ip = ""
                    addressWords = ps.minSpaces(lines[i+2].lower()).split(" ")
                    ip = addressWords[0].replace(",", "")
                    # get interface IPv6 prefix
                    network = ""
                    for j in range(len(addressWords)):
                        if addressWords[j] == "subnet":
                            network = addressWords[j+2]
                            break
                    # calculate first two hexadecimals
                    [first, sec] = n.first2Hextets(network)
                    # add IPv6 data to address list
                    ipv6.append({"Interface": interface, "Network": network, "Assigned": ip, "First Hex": first, "Sec Hex": sec, "Link-Local": linkLocal})
                    i += 1
                i += 1
        i += 1
    return [ipv4, ipv6]

def getInterfaces(session, expec):
    interfaces = []
    # get all interfaces and descriptions
    cmd = "show interfaces description"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[1:-1])
    # loop over table
    for row in table[1:]:
        # change port nomenclature
        port = row[col["Interface"]]
        port = port.replace("Vl", "Vlan")
        interfaces.append({"Interface": port, "Description": row[col["Description"]], "Status": row[col["Status"]], "Vlan": ""})
    # get Vlan
    cmd = "show interfaces status"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[1:-1])
    # loop over table
    for row in table[1:]:
        port = row[col["Port"]]
        for i in range(len(interfaces)):
            if interfaces[i]["Interface"] == port:
                interfaces[i]["Vlan"] = row[col["Vlan"]]
                break
    return interfaces

def getMACs(session, expec):
    macs = []
    # get MAC address table
    cmd = "show mac address-table | exclude igmp|system"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[2:-5])
    # loop over table
    for row in table[1:]:
        # change port nomenclature
        port = row[col["port"]]
        port = port.replace("Port-channel", "Po")
        port = port.replace("TenGigabitEthernet", "Te")
        # collect MAC addresses
        macs.append({"MAC": row[col["mac address"]], "Interface": port, "Type": row[col["type"]], "Time": int(time.time())})
    return macs

def getARPs(session, expec):
    arps = []
    # get ARP table
    cmd = "show ip arp"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[1:-1])
    # loop over table
    for row in table[1:]:
        # determine ARP type
        if row[col["(min)"]] == "-":
            arpType = "static"
        else:
            arpType = "dynamic"
        # change port nomenclature
        port = row[col["Interface"]]
        port = port.replace("Port-channel", "Po")
        port = port.replace("TenGigabitEthernet", "Te")
        # collect ARPs
        if row[col["Hardware Addr"]] != "Incomplete":
            arps.append({"Address": row[col["Address"]], "MAC": row[col["Hardware Addr"]], "Interface": port, "Type": arpType, "Time": int(time.time())})
    return arps

def getInterfaceRates(session, expec):
    interfaces = []
    # get interface rates
    cmd = "show interfaces summary | begin Interface"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[1:-1])
    # loop over table
    for row in table[1:]:
        # change port nomenclature
        port = row[col["Interface"]]
        port = port.replace("Port-channel", "Po")
        port = port.replace("TwentyFiveGigE", "Twe")
        port = port.replace("GigabitEthernet", "Gi")
        port = port.replace("HundredGigE", "Hu")
        port = port.replace("Loopback", "Lo")
        # collect transmit and receive rate in bits/sec
        trans = int(row[col["TXBS"]])
        rec = int(row[col["RXBS"]])
        interfaces.append({"Interface": port, "Transmit": trans, "Recieve": rec})
    return interfaces

def getRoute(session, expec, address):
    ### same function as Cisco 9500, Cisco 4500, and Cisco CBR8 ###
    route = {"Network": "No route.", "Process": "-", "Next-Hop": "None", "Interface": "-", "Child-Hop": ""}
    # if this is an IPv6 network
    if ":" in address:
        if address == "::":
            address = "::/0"
        cmd = "show ipv6 route "+address
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # loop over the output
        routeBlock = False
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if routeBlock:
                route["Next-Hop"] = line.split(" ")[0].lower().replace(",","")
                # if this is a ultimate route (has a exit interface)
                if "," in line or "via" in line:
                    # if this is a local route (IP is configured on this device)
                    if route["Process"] == "local":
                        route["Next-Hop"] = "None"
                    # if the IP is routed by this device
                    elif route["Process"] == "connected":
                        route["Next-Hop"] = address
                    # get the exit interface
                    routeWords = line.split(" ")
                    route["Interface"] = routeWords[len(routeWords)-1].lower()
                # if this is a child route
                else:
                    # rerun to find the ultimate route
                    childHop = route["Next-Hop"]
                    route = getRoute(session, expec, route["Next-Hop"])
                    # replace network with previous entry
                    route["Network"] = network
                    route["Process"] = process
                    # remember child route
                    route["Child-Hop"] = childHop
                break
            else:
                if "Routing entry for" in line:
                    # determine the network entry
                    network = ps.returnN(line, 3).lower()
                    route["Network"] = network
                elif "Known via" in line:
                    # determine the process the route was learned through
                    line = line[line.find("\"")+1:]
                    process = line[:line.find("\"")]
                    route["Process"] = process
                elif "Routing paths" in line:
                    # if the section containing the next hop will start next line
                    routeBlock = True
    else:
        cmd = "show ip route "+address
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # if no route was found
        if "not in table" in lines[1]:
            # get the default route
            cmd = "show ip route 0.0.0.0"
            lines = p_ext.sendCMD(session, cmd, expec, 10)
        # loop over the output
        routeBlock = False
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if routeBlock:
                # if this is the selected route
                if "*" in line:
                    route["Next-Hop"] = ps.returnN(line, 1).replace(",","").replace("directly","None")
                    # if this is a ultimate route (has a exit interface)
                    if "via" in line:
                        port = ps.returnN(line, len(line.split(" "))-1)
                        route["Interface"] = port
                    # if this is a child route
                    else:
                        # rerun to find the ultimate route
                        childHop = route["Next-Hop"]
                        route = getRoute(session, expec, route["Next-Hop"])
                        # replace network with previous entry
                        route["Network"] = network
                        route["Process"] = process
                        # remember child route
                        route["Child-Hop"] = childHop
                    break
            else:
                if "Routing entry for" in line:
                    # determine the network entry
                    network = ps.returnN(line, 3).replace(",","")
                    route["Network"] = network
                elif "Known via" in line:
                    # determine the process the route was learned through
                    line = line[line.find("\"")+1:]
                    process = line[:line.find("\"")]
                    route["Process"] = process
                elif "Routing Descriptor Blocks" in line:
                    # if the section containing the next hop will start next line
                    routeBlock = True
    return route

###############
##### NEW #####
###############
import re

def get_ips(device, link_local=True):
    ipv4 = []
    ipv6 = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all IP interfaces
    matches = re.finditer(r"^interface (?P<interface>((Loopback|Port-channel|Vlan|VirtualPortGroup)\d+|(TwentyFiveGigE|HundredGigE)\d+/\d+/\d+(\.\d+)?|TenGigabitEthernet\d+/\d+(/\d+)?))\n"+
                          r"( .+\n)+", device.config, re.M)
    # for each IP interface
    for match in matches:
        # get the interface name
        interface = match.group('interface')
        # get IPv4 addresses
        ip_matches = re.finditer(r"^ ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'), netmask=ip_match.group('netmask'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv4 data to address list
                #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
                ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
        # get IPv6 addresses
        ip_matches = re.finditer(r"^ ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # calculate the first three half-hextets
                first_hex, sec_hex, third_hex = ip.first_three
                # add IPv6 data to address list
                #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
                ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    if link_local:
        # get IPv6 link-local addresses
        cmd = "show ipv6 interface | include protocol|link-local"
        device.get_response(cmd)
        matches = re.finditer(r"^(?P<interface>((Loopback|Port-channel|Vlan|VirtualPortGroup)\d+|(TwentyFiveGigE|HundredGigE)\d+/\d+/\d+(\.\d+)?|TenGigabitEthernet\d+/\d+(/\d+)?)) is .*\n"+
                              r"  IPv6 is enabled, link-local address is (?P<ip>[\da-fA-F:]+)", device.response, re.M)
        for match in matches:
            # get the interface name
            interface = match.group('interface')
            # get the IP address
            ip = n.IP(match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add the address to the previous entries
                for i in range(len(ipv6)):
                    if ipv6[i]['Interface'] == interface:
                        ipv6[i]['Link-Local'] = ip.addr
#                    if ipv6[i]['interface'] == interface:
 #                       ipv6[i]['link_local'] = ip.addr
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
            #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.nth(1).split('/')[0], 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
            ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.nth(1).split('/')[0], 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get IPv6 aggregate routes
    interface = 'PD'
    matches = re.finditer(r"^ipv6 route (?P<ip>[\da-fA-F:]+/\d{1,3}) Null", device.config, re.M)
    for match in matches:
        # get the network
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # calculate the first three half-hextets
            first_hex, sec_hex, third_hex = ip.first_three
            # add IPv6 data to address list
            #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
            ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    # get IPv4 addresses
#    cmd = "show interfaces"
 #   device.get_response(cmd)
  #  # search the output
   # pattern = re.compile(r"^(?P<interface>\S+) is (?P<state>[\S ]+), line protocol is (?P<proto>\S+).*\n"+
    #                     r"((  )+.*\n)*"+
     #                    r"(  )+Internet address is (?P<ip>[\d./]+)", re.M)
#    matches = pattern.finditer(device.response)
 #   # for each match
  #  for match in matches:
   #     ip = n.IP(match.group('ip'))
    #    if ip.valid:
     #       # add IPv4 data to address list
      #      ipv4.append({'Interface': match.group('interface'), 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get static routes
#    cmd = "show running-config | include ^ip\ route"
 #   device.get_response(cmd)
  #  # search the output
   # pattern = re.compile(r"^ip route (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3}) \S+[ ]+name (?P<interface>\S+)", re.M)
    #matches = pattern.finditer(device.response)
    # for each match
#    for match in matches:
 #       ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
  #      if ip.valid:
   #         # add IPv4 data to address list
    #        ipv4.append({'Interface': match.group('interface'), 'Network': ip.network, 'Assigned': ip.nth(1).split('/')[0], 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get IPv6 addresses
#    cmd = "show ipv6 interface"
 #   device.get_response(cmd)
  #  # search the output
   # pattern = re.compile(r"^(?P<interface>\S+) is (?P<state>[\S ]+), line protocol is (?P<proto>\S+).*\n"+
    #                     r"(  )+IPv6 is enabled, link-local address is (?P<link_local>[\da-fA-F:]+).*\n"+
     #                    r"((  )+.*\n)*"+
      #                   r"(  )+(?P<ip>[\dA-F:]+), subnet is [\da-fA-F:]+/(?P<prefix>\d{1,3})", re.M)
#    matches = pattern.finditer(device.response)
 #   # for each match
  #  for match in matches:
   #     ip = n.IP(match.group('ip')+'/'+match.group('prefix'))
    #    link_local = n.IP(match.group('link_local'))
     #   if ip.valid and link_local.valid:
      #      first, sec = n.first2Hextets(ip.network)
       #     # add IPv6 data to address list
        #    ipv6.append({'Interface': match.group('interface'), 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec, 'Link-Local': link_local.addr})
    return ipv4, ipv6

def interface_fullname(interface):
    interfaces = [
                                # 9500
                                ['Vl', 'Vlan'],
                                ['Gi', 'GigabitEthernet'],
                                ['Twe', 'TwentyFiveGigE'],
                                ['Hu', 'HundredGigE'],
                                ['Po', 'Port-channel'],
                                ['Lo', 'Loopback'],
                                # 4500
                                ['Fa', 'FastEthernet'],
                                ['Te', 'TenGigabitEthernet']
                              ]
    for correction in interfaces:
        if interface.startswith(correction[0]) and not interface.startswith(correction[1]):
            interface = interface.replace(correction[0], correction[1])
            break
    return interface

def get_interfaces(device):
    interfaces = []
    # get all interfaces and descriptions
    cmd = "show interfaces description"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<interface>\S+)[ ]+(?P<status>(admin down|down|up))[ ]+\S+[ ]+(?P<description>[\S ]+)?(?=\n)", device.response, re.M)
    for match in matches:
        interface = interface_fullname(match.group('interface'))
        description = match.group('description')
        if description is None:
            description = ''
        interfaces.append({'Interface': interface, 'Description': description, 'Status': match.group('status'), 'Vlan': ''})
    # get Vlan
    cmd = "show interfaces status"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<interface>\S+)[ ]+[\S ]+[ ]+(connected|notconnect|disabled)[ ]+(?P<vlan>[0-9a-zA-Z]+)[ ]+", device.response, re.M)
    for match in matches:
        interface = interface_fullname(match.group('interface'))
        vlan = match.group('vlan')
        for i in range(len(interfaces)):
            if interfaces[i]['Interface'] == interface:
                interfaces[i]['Vlan'] = vlan
                break
    return interfaces

def get_MACs(device):
    macs = []
    # get MAC address table
    #cmd = "show mac address-table | until Multicast Entries | exclude (static|STATIC)"
    cmd = "show mac address-table"
    output = device.get_response(cmd)
    matches = re.finditer(r"(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<type>dynamic|DYNAMIC)[ ]+(\S+[ ]+)?(?P<interface>\S+)", device.response)
    for match in matches:
        interface = interface_fullname(match.group('interface'))
        macs.append({'MAC': match.group('mac'), 'Interface': interface, 'Type': match.group('type').lower(), 'Time': int(time.time())})
    return macs

def get_ARPs(device):
    arps = []
    # get ARP table
    cmd = "show ip arp"
    device.get_response(cmd)
    matches = re.finditer(r"^Internet[ ]+(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(?P<type>\d+|-)[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\S+[ ]+(?P<interface>\S+)", device.response, re.M)
    for match in matches:
        interface = interface_fullname(match.group('interface'))
        if match.group('type') == '-':
            arpType = "static"
        arpType = "static" if match.group('type') == '-' else "dynamic"
        arps.append({'Address': match.group('ip'), 'MAC': match.group('mac'), 'Interface': interface, 'Type': arpType, 'Time': int(time.time())})
    return arps

def get_route(device, address):
    route = {'Network': '', 'Process': '', 'Next-Hop': '', 'Interface': '', 'Child-Hop': ''}
    # if this is an IPv4 network
    if address.type == 4:
        # get route
        cmd = "show ip route "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>(\d{1,3}\.){3}\d{1,3}/\d{1,3}).*\n"+
                                            r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                            r"([ ]+.*\n)+"+
                                            r"[ ]+\*[ ]+(?P<next_hop>(\d{1,3}\.){3}\d{1,3}|directly connected)(, (.*via (?P<interface>\S+))?)?", device.response, re.M)
        if match is not None:
            route['Network'] = match.group('network')
            route['Next-Hop'] = match.group('next_hop').lower()
            route['Process'] = match.group('process')
            if route['Process'] == 'connected':
                route['Next-Hop'] = None
            if match.group('interface') is not None:
                route['Interface'] = match.group('interface')
            # if this is a child route
            else:
                # rerun to find the ultimate route
                childHop = route['Next-Hop']
                network = route['Network']
                process = route['Process']
                route = get_route(device, n.IP(route['Next-Hop']))
                # replace network with previous entry
                route['Network'] = network
                route['Process'] = process
                # remember child route
                route['Child-Hop'] = childHop
                if route['Process'] != 'connected':
                    route['Next-Hop'] = childHop
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
            route['Network'] = match.group('network')
            route['Next-Hop'] = match.group('next_hop').lower()
            route['Process'] = match.group('process')
            if route['Process'] == 'connected':
                route['Next-Hop'] = None
            if match.group('interface') is not None:
                route['Interface'] = match.group('interface')
            # if this is a child route
            else:
                # rerun to find the ultimate route
                childHop = route['Next-Hop']
                network = route['Network']
                process = route['Process']
                route = get_route(device, n.IP(route['Next-Hop']))
                # replace network with previous entry
                route['Network'] = network
                route['Process'] = process
                # remember child route
                route['Child-Hop'] = childHop
    return route

############################################################
############### Status Checks ##############################
############################################################
def get_all_mcounts(device):
    mcounts = []
    # get the output
    cmd = "show ip mroute count"
    device.get_response(cmd)
    # get each multicast
    matches = re.finditer(r"^Group: (?P<dst>(\d{1,3}\.){3}\d{1,3}), Source count: \d+, Packets forwarded: (?P<pkt_fwd>\d+), Packets received: (?P<pkt_rec>\d+)\n"+
                          r"  Source: (?P<src>(\d{1,3}\.){3}\d{1,3})", device.response, re.M)
    # for each match
    for match in matches:
        # collect multicast data
        mcount = {'dst': match.group('dst'), 'src': match.group('src'), 'fwd': int(match.group('pkt_fwd')), 'rec': int(match.group('pkt_rec'))}
        mcounts.append(mcount)
    return mcounts

def get_all_interface_states(device):
    interfaces = []
    # get the output
    cmd = "show interfaces description"
    device.get_response(cmd)
    # get each interface
    matches = re.finditer(r"^(?P<name>[\w\-]+[\d/]+)[ ]+(?P<status>(up|down|admin down))[ ]+(?P<proto>(up|down))", device.response, re.M)
    # for each match
    for match in matches:
        interface = {'name': match.group('name'), 'status': match.group('status'), 'proto': match.group('proto')}
        interfaces.append(interface)
    return interfaces

def get_ipv4_states(device, dest):
    interfaces = []
    # get the output
    cmd = "show ip interface brief"
    device.get_response(cmd)
    # get each interface
    matches = re.finditer(r"^(?P<name>[\w\-]+[\d/]+)[ ]+(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+\w+[ ]+\w+[ ]+(?P<status>(up|down|administratively down))[ ]+(?P<proto>(up|down))", device.response, re.M)
    # for each match
    for match in matches:
        status = match.group('status').replace('administratively', 'admin')
        interface = {'name': match.group('name'), 'ip': match.group('ip'), 'status': status, 'proto': match.group('proto')}
        interfaces.append(interface)
    # for each interface
    for i in range(len(interfaces)):
        # if the interface is up
        if interfaces[i]['proto'] == 'up':
            # test a ping to the supplied destination
            cmd = f"ping {dest} source {interfaces[i]['ip']}"
            device.get_response(cmd)
            # get the results
            match = re.search(r"^Success rate is \d+ percent \((?P<rec>\d+)/(?P<sent>\d+)\)", device.response, re.M)
            if match is not None:
                interfaces[i]['sent'] = match.group('sent')
                interfaces[i]['rec'] = match.group('rec')
    return interfaces

def get_ipv6_states(device, dest):
    interfaces = []
    # get the output
    cmd = "show ipv6 interface brief"
    device.get_response(cmd)
    # get each interface
    matches = re.finditer(r"^(?P<name>[\w\-]+[\d/]+)[ ]+\[(?P<status>(up|down|administratively down))/(?P<proto>(up|down))\]\n"+
                          r"    [0-9a-fA-F:]+\n"+
                          r"    (?P<ip>[0-9a-fA-F:]+)", device.response, re.M)
    for match in matches:
        status = match.group('status').replace('administratively', 'admin')
        interface = {'name': match.group('name'), 'ip': match.group('ip'), 'status': status, 'proto': match.group('proto')}
        interfaces.append(interface)
    # for each interface
    for i in range(len(interfaces)):
        # if the interface is up
        if interfaces[i]['proto'] == 'up':
            # test a ping to the supplied destination
            cmd = f"ping ipv6 {dest} source {interfaces[i]['ip']}"
            device.get_response(cmd)
            # get the results
            match = re.search(r"^Success rate is \d+ percent \((?P<rec>\d+)/(?P<sent>\d+)\)", device.response, re.M)
            if match is not None:
                interfaces[i]['sent'] = match.group('sent')
                interfaces[i]['rec'] = match.group('rec')
    return interfaces

