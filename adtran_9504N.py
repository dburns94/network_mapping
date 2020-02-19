#!/usr/bin/python3.6

import sys
import networking as n
import pexpect_ext as p_ext
import parseString as ps
import re_ext
import re

def noPaging(session, expec):
    cmd = "terminal length 0"
    p_ext.sendCMD(session, cmd, expec, 10)

def getSwVersion(session, expec):
    version = "Unknown"
    cmd = "show version | include image"
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    pattern = r"\"\S+?\.(\S+)\""
    match = re_ext.getMatch(output, pattern)
    if match != None:
        version = match.group(1).upper()
    return version

def getHostname(session, cmd):
    hostname = ""
    lines = p_ext.sendCMD(session, cmd, ".*#", 5)
    for i in lines:
        if "#" in i:
            hostname = i[0:i.find("#"):1]
    return hostname

# cmts-status info gathering
def ipConnectivity(device, ips, iphelper):
    results = []
    ip_type = ''
    for ip in ips:
        sys.stdout.write('.')
        if ':' in ip['address']:
            ip_type = 'v6'
        # get the response
        cmd = f"ping ip{ip_type} {iphelper} source {ip['address'].split('/')[0]}"
        device.get_response(cmd, timeout=15)
        # get packet count
        match = re.search(r"^Success rate is .+ percent \((?P<received>\d+)/(?P<sent>\d+)\)", device.response, re.M)
        if match is not None:
            results.append({'ip': ip['address'], 'recieved': match.group('received'), 'transmitted': match.group('sent')})
    return results

def channelStatus(device, mac, DS, US):
    status = []
    sys.stdout.write('.')
    # get the response
    cmd = f"show interface {mac}"
    device.get_response(cmd)
    # get the power
    power = '-'
    match = re.search(r"tx power (?P<power>\d+(.\d+)?) dBm", device.response)
    if match is not None:
        power = match.group('power')
    # get the channel status
    match = re.search(r"^"+mac+r".* is (?P<status>[\S ]+)", device.response, re.M)
    if match is not None:
        status.append({'channel': mac, 'status': match.group('status').replace('administratively','admin'), 'frequency': '-', 'power': power})
    return [status, []]

def cmCount(device, mac):
    count = {'online': 0, 'total': 0}
    # get the cable-mac number
    number = None
    match = re.search(r"\d+/\d+", mac)
    if match is not None:
        number = match.group(0)
    # if the cable-mac number was found
    if number is not None:
        # get cable modem summary
        cmd = "show cable modem summary"
        device.get_response(cmd)
        # get the modem counts
        match = re.search(r"^C"+number+r"[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<unregistered>\d+)[ ]+(?P<offline>\d+)", device.response, re.M)
        if match is not None:
            count['total'] = int(match.group('total'))
            count['online'] = int(match.group('registered'))
    return count

###########################################
# network functions
###########################################
def getAllIPs(session, expec):
    ### same function as ADTRAN 9504N and ADTRAN 9516 ###
    ipv4 = []
    cmd = "show ip interface | include is\ up,\ line\ protocol|\/"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-2:
        if "line protocol" in lines[i]:
            # get interface
            interface = lines[i].split(" ")[0]
            while "line protocol" not in lines[i+1] and "#" not in lines[i+1]:
                # get interface IPv4 address and subnet
                addressWords = ps.minSpaces(lines[i+1]).split(" ")
                ip = addressWords[len(addressWords)-1]
                network = n.nthIPv4(ip, 0)
                # add IPv4 data to address list
                ipv4.append({"Interface": interface, "Network": network, "Assigned": ip.split("/")[0], "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
                i += 1
        i += 1
    # get eth0 address
    cmd = "show interface eth0"
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    # look for the IP
    pattern = r"^eth0\ .*\ up(.*\n)*\ ip\ address:\ (?P<network>(?P<assigned>([0-9]{1,3}\.){3}[0-9]{1,3})/\d{1,2})"
    match = re_ext.getMatch(output, pattern)
    if match != None:
        interface = "eth0"
        assigned = match.group("assigned")
        network = n.nthIPv4(match.group("network"), 0)
        # add IPv4 data to address list
        ipv4.append({"Interface": interface, "Network": network, "Assigned": assigned, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
    # get IPv6 addresses that are up/up
    ipv6_up = []
    cmd = "show ipv6 interface"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-2:
        if "is up, line protocol" in lines[i]:
            # get interface
            interface = lines[i].split(" ")[0]
            while "line protocol" not in lines[i+1] and "Joined group" not in lines[i+1] and "#" not in lines[i+1]:
                addressWords = ps.minSpaces(lines[i+1]).split(" ")      
                if "link-local" in lines[i+1]:
                    # get link-local address
                    linkLocal = addressWords[len(addressWords)-1]
                elif n.validIPv6(addressWords[0]):
                    # get IPv6 address
                    ip = addressWords[0]
                    ipv6_up.append({"Interface": interface, "Network": "", "Assigned": ip, "First Hex": -1, "Sec Hex": -1, "Link-Local": linkLocal})
                i += 1
        i += 1
    # get all IPv6 addresses
    ## this is done because the output of 'show ipv6 interface' does not include prefix size
    ipv6_all = []
    cmd = "show running-config | include ^interface|^[ ]ip[v][6][ ]address"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # initialize variable
    interface = ""
    # loop over the response
    for line in lines[1:-1]:
        line = ps.minSpaces(line)
        firstWord = ps.returnN(line, 0)
        if firstWord == "interface":
            interface = ps.returnN(line, 1)
            # change interface nomenclature
            interface = interface.replace("Port-channel", "Po")
            interface = interface.replace("TenGi", "Te")
            interface = interface.replace("Loopback", "Lo")
        elif firstWord == "ipv6":
            ip = ps.returnN(line, 2).lower()
            network = n.nthIPv6(ip, 0).lower()
            # calculate first two hexadecimals
            [first, sec] = n.first2Hextets(network)
            ipv6_all.append({"Interface": interface, "Network": network, "Assigned": ip.split("/")[0], "First Hex": first, "Sec Hex": sec})
    # match the corresponding prefix size to the IPv6 up/up interfaces
    ipv6 = []
    for ip_up in ipv6_up:
        for ip_all in ipv6_all:
            if ip_up["Assigned"] == ip_all["Assigned"]:
                ip_up["Network"] = ip_all["Network"]
                ip_up["First Hex"] = ip_all["First Hex"]
                ip_up["Sec Hex"] = ip_all["Sec Hex"]
                ipv6.append(ip_up)
                break
    # get IPv6 static routes as prefix delegations
    cmd = "show running-config | include ^ipv6\ route"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    interface = "PD"
    # loop over the response
    for line in lines[1:-1]:
        match = re_ext.getMatch(line, r"^ipv6\ route\ (?P<network>(?P<assigned>[\da-f:]+)/\d{1,3})")
        if match != None:
            network = match.group("network")
            assigned = match.group("assigned")
            # calculate first two hexadecimals
            [first, sec] = n.first2Hextets(network)
            ipv6.append({"Interface": interface, "Network": network, "Assigned": assigned, "First Hex": first, "Sec Hex": sec})
    return [ipv4, ipv6]

def getRoute(session, expec, address):
    ### same function as CASA C100G, ADTRAN 9504N and ADTRAN 9516 ###
    route = {"Network": "", "Process": "", "Next-Hop": "", "Interface": "", "Child-Hop": ""}
    # if this is an IPv6 network
    if ":" in address:
        cmd = "show ipv6 route "+address
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # loop over the output
        routeBlock = False
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if routeBlock:
                # if this is a ultimate route (has a exit interface)
                if "*" in line or "connected" in line:
                    routeWords = line.split(" ")
                    # get the next-hop address
                    route["Next-Hop"] = routeWords[2].lower().replace(",","")
                    # if this is a local route (IP is configured on this device)
                    if route["Process"] == "local":
                        route["Next-Hop"] = "None"
                    # if the IP is routed by this device
                    elif route["Process"] == "connected":
                        route["Next-Hop"] = address
                    # get the exit interface
                    for i in range(len(routeWords)):
                        if "," in routeWords[i]:
                            route["Interface"] = routeWords[i+1]
                            break
                    break
            else:
                if "Routing entry for" in line:
                    # determine the network entry
                    network = ps.returnN(line, 3)
                    route["Network"] = network
                elif "Known via" in line:
                    # determine the process the route was learned through
                    line = line[line.find("\"")+1:]
                    process = line[:line.find("\"")]
                    route["Process"] = process
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
                    routeWords = line.split(" ")
                    # get the next hop address
                    route["Next-Hop"] = routeWords[1].replace(",","").replace("is","None")
                    i = 1
                    while i < len(routeWords)-1:
                        if "," in routeWords[i]:
                            if routeWords[i+1] == "via":
                                route["Interface"] = routeWords[i+2]
                            else:
                                route["Interface"] = routeWords[i+1]
                            break
                        i += 1
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
                    # if the section containing the next hop will start next line
                    routeBlock = True
    return route

###################################################################################
## Global
###################################################################################

# initial SG info gathering
def cmCountTotal(session, expec):
    count = {'online': 0, 'total': 0}
    cmd = "show cable modem summary total | include Total"
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    pattern = r"^Total:[ ]+(\d+)[ ]+(\d+)"
    match = re_ext.getMatch(output, pattern)
    if match != None:
        count['total'] = match.group(1)
        count['online'] = match.group(2)
    return count

# CMTS operations
def clearModems(session, expec):
    cmd = "clear cable modem offline delete"
    lines = p_ext.sendCMD(session, cmd, expec, 20)

###############
##### NEW #####
###############
import re
import casa_c100g as c100g

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show version | include image"
    device.get_response(cmd)
    print(device.response)
    # parse the response
    match = re.search(r"^System image file is \".*(?P<version>dpoe\S+)\"", device.response, re.M)
    if match is not None:
        version = match.group('version').strip().upper()
    return version

############################################################
############### Networking #################################
############################################################
def get_ips(device, link_local=True):
    ipv4 = []
    ipv6 = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all IP interfaces
    matches = re.finditer(r"^interface (?P<interface>((Loopback|Bundle|Port-channel|eth)\d+(\.\d+)?|TenGi\d+/\d+))\n"+
                          r"( .+\n)+", device.config, re.M)
    # for each IP interface
    for match in matches:
        # get the interface name
        interface = match.group('interface').replace('TenGi','TenGigabitEthernet')
        # get IPv4 addresses
        ip_matches = re.finditer(r"^ ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv4 data to address list
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
        matches = re.finditer(r"^(?P<interface>((Loopback|Bundle|Port-channel|eth)\d+(\.\d+)?|TenGi\d+/\d+)).*\n"+
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
            ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    return ipv4, ipv6

def get_route(device, address):
    # same as CASA C100G
    return c100g.get_route(device, address)

############################################################
############### DOCSIS #####################################
############################################################
## Chassis
def get_total_cm_count(device):
    count = {'online': 0, 'total': 0}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # parse the response
    matches = re.finditer(r"^C\d+/\d+[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)", device.response, re.M)
    for match in matches:
        count['online'] += int(match.group('registered'))
        count['total'] += int(match.group('total'))
    return count

## MAC Domain
def get_mac_domains(device):
    macs = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all mac-domains
    matches = re.finditer(r"^interface (?P<mac>Tpon\d+/\d+)\n", device.config, re.M)
    for match in matches:
        mac = match.group('mac')
        if mac not in macs:
            macs.append(mac)
    # sort the MACs
    macs.sort()
    return macs

def get_mac_description(device, mac):
    description = 'Open'
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get the description
    match = re.search(r"^interface "+mac+r"\n"+
                      r"( .+\n)*"+
                      r" description (?P<description>[\S ]+)", device.config, re.M)
    if match is not None:
        description = match.group('description').strip()
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    match = re.search("\d+/\d+", mac)
    if match is not None:
        DS = match.group(0)
        US = match.group(0)
    return DS, US

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    match = re.search("\d+/\d+", mac)
    if match is not None:
        counts['DS'] = 1
        counts['US'] = 1
    return counts

def get_mac_cm_counts(device, mac):
    counts = {'online': 0, 'total': 0, 'percent': 100}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the cable-mac number
    number = None
    match = re.search(r"\d+/\d+", mac)
    if match is not None:
        number = match.group(0)
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^C"+number+r"[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<unregistered>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
        if match is not None:
            counts['total'] = int(match.group('total'))
            counts['online'] = int(match.group('registered'))
            if counts['total'] > 0:
                counts['percent'] = round((counts['online']/counts['total'])*100, 1)
    return counts

def get_mac_IP_interface(device, mac):
    interface = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get the IP interface
    match = re.search(r"^interface "+mac+r"\n"+ 
                      r"( .+\n)*"+ 
                      r" cable bundle (?P<interface>\d+)", device.config, re.M)
    if match is not None:
        interface = f"Bundle{match.group('interface')}"
    return interface

def get_mac_IPs(device, interface):
    ipv4 = []
    ipv6 = []
    ipv4helper = []
    ipv6helper = []
    # if no IP interface was found
    if interface is None:
        return ipv4, ipv4helper, ipv6, ipv6helper
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get ip-bundle config
    matches = re.finditer(r"^interface (?P<interface>"+interface+r"(\.\d+)?)\n"+
                          r"( .+\n)+", device.config, re.M)
    for match in matches:
        interface = match.group('interface')
        bundle_config = match.group(0)
        # get IPv4 addresses
        matches = re.finditer(r"^ ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'))
            if ip.valid:
                ipv4.append({'interface': interface, 'address': str(ip)})
        # get IPv4 helpers
        matches = re.finditer(r"^ cable helper-address (?P<ip>(\d{1,3}\.){3}\d{1,3})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'))
            if ip.valid and ip.addr not in ipv4helper:
                ipv4helper.append(ip.addr)
        # get IPv6 addresses
        matches = re.finditer(r"^ ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'))
            if ip.valid:
                ipv6.append({'interface': interface, 'address': str(ip)})
        # get IPv6 helpers
        matches = re.finditer(r"^ ipv6 dhcp relay destination (?P<ip>[\da-fA-F:]+)", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'))
            if ip.valid and ip.addr not in ipv6helper:
                ipv6helper.append(ip.addr)
    return ipv4, ipv4helper, ipv6, ipv6helper

############################################################
############### CM #########################################
############################################################
def get_modem(device, modem, query_value, query_type):
    # declare command set
    cmd_sets = {
                'MAC':  [
                         f'show cable modem {query_value}',
                         f'show cable modem cpe device-type | include {query_value}'
                        ],
                'IPv4': [
                         f'show cable modem {query_value}',
                         f'show cable modem cpe device-type | include {query_value}'
                        ],
                'IPv6': [
                         f'show cable modem {query_value}',
                         f'show cable modem ipv6 cpe device-type | include {query_value}'
                        ]
               }
    # get commands to run
    cmds = None
    for key, cmd_set in cmd_sets.items():
        if key.lower() in query_type.lower():
            cmds = cmd_set
    # for each command
    modem.output = ''
    for cmd in cmds:
        cpe_mac = False
        # send the command
        device.get_response(cmd)
        modem.output += '\n'+device.response
        # search the output for the MAC
        match = re.search(r".*\b(?P<cm_mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})\b.*\b(?P<cpe_mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})\b", device.response)
        if match is not None:
            cpe_mac = True
            modem.output = device.response
            cmd = f"show cable modem {match.group('cm_mac')}"
            device.get_response(['', cmd])
        match = re.search(r"^(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<ip>((\d{1,3}\.){3}\d{1,3})|-+)[ ]+"+
                          r"C\d{1,2}/\d{1,2}\S*[ ]+(?P<state>\S+)[ ]+", device.response, re.M)
        if match is not None:
            modem.mac = match.group('mac')
            modem.state = match.group('state')
            if 'offline' not in modem.state.lower():
                modem.offline = False
            else:
                modem.offline = True
            ip = match.group('ip')
            if len(ip.replace('-','')) > 0:
                modem.ipv4 = ip
            else:
                # get the IPv6 address
                cmd = f"show cable modem {modem.mac} verbose | include IPV6"
                device.get_response(['', cmd])
                modem.output += '\n'+device.response
                match = re.search(r"[\da-fA-F:]+:[\da-fA-F:]+", device.response)
                if match is not None:
                    modem.ipv6 = match.group(0).lower()
            break
#    if match is None:
 #       modem.output = modem.output[1:]
    return modem

