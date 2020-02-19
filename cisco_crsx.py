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
    lines = p_ext.sendCMD(session, cmd, expec, 15)
    for line in lines[1:-1]:
        if "Version" in line:
            line = line[line.find("Version")+8:]
            version = line[:line.find("[")]
    return version

def getSN(session, expec):
    sn = ""
    cmd = "admin show inventory | include PID: ASR-9006-AC"
    lines = p_ext.sendCMD(session, cmd, expec, 15)
    for line in lines[2:-1]:
        line = ps.minSpaces(line)
        sn = line[line.find("SN: ")+4:]
    return sn

def getAllIPs(session, expec):
    ipv4 = []
    # get only up/up IPs
    #cmd = "show ipv4 interface | utility egrep \"is\ Up,\ ipv4\ protocol|Internet\ address\ is\""
    cmd = "show ipv4 interface | utility egrep \"ipv4\ protocol|Internet\ address\ is\""
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-2:
        if "ipv4 protocol" in lines[i]:
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
    # get only up/up IPs
    #cmd = "show ipv6 interface | utility egrep \"is\ Up,\ ipv6\ protocol|link-local\ address\ is|subnet\ is\""
    cmd = "show ipv6 interface | utility egrep \"ipv6\ protocol|link-local\ address\ is|subnet\ is\""
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-3:
        if "ipv6 protocol" in lines[i]:
            if "address" in lines[i+1]:
                # get interface
                interface = lines[i].split(" ")[0]
                # get link-local address
                linkLocal = ""
                linkWords = ps.minSpaces(lines[i+1]).split(" ")
                for j in range(len(linkWords)):
                    if linkWords[j] == "link-local":
                        linkLocal = linkWords[j+3]
                        break
                while "subnet is" in lines[i+2]:
                    # get interface IPv6 address
                    ip = ""
                    addressWords = ps.minSpaces(lines[i+2]).split(" ")
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
        port = row[col["Interface"]]
        interfaces.append({"Interface": port, "Description": row[col["Description"]], "Status": row[col["Status"]], "Vlan": ""})
    # get Vlan
    # not supported
    return interfaces

def getMACs(session, expec):
    macs = []
    # get MAC address table
    cmd = "show arp | exclude CPU"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[2:-1])
    # loop over table
    for row in table[1:]:
        # change port nomenclature
        port = row[col["Interface"]]
        port = port.replace("Bundle-Ether", "BE")
        port = port.replace("TenGigE", "Te")
        # collect MAC addresses
        if n.validMAC(row[col["Hardware Addr"]]):
            macType = row[col["State"]]
            macType = macType.replace("Interface", "static")
            macType = macType.replace("Dynamic", "dynamic")
            macs.append({"MAC": row[col["Hardware Addr"]], "Interface": port, "Type": macType, "Time": int(time.time())})
    return macs

def getARPs(session, expec):
    arps = []
    # get ARP table
    cmd = "show arp | exclude CPU"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[2:-1])
    # loop over table
    for row in table[1:]:
        # change port nomenclature
        port = row[col["Interface"]]
        port = port.replace("Bundle-Ether", "BE")
        port = port.replace("TenGigE", "Te")
        # collect ARPs
        if n.validIPv4(row[col["Address"]]):
            arpType = row[col["State"]]
            arpType = arpType.replace("Interface", "static")
            arpType = arpType.replace("Dynamic", "dynamic")
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
        port = port.replace("TenGigabitEthernet", "Te")
        port = port.replace("FastEthernet", "Fa")
        port = port.replace("Loopback", "Lo")
        # collect transmit and receive rate in bits/sec
        trans = int(row[col["TXBS"]])
        rec = int(row[col["RXBS"]])
        interfaces.append({"Interface": port, "Transmit": trans, "Recieve": rec})
    return interfaces

def getRoute(session, expec, address):
    route = {"Network": "", "Process": "", "Next-Hop": "", "Interface": "", "Child-Hop": ""}
    # if this is an IPv6 network
    if ":" in address:
        # run route command
        cmd = "show route ipv6 "+address
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # loop over the output
        routeBlock = False
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if routeBlock:
                # if this is the selected route
                if "from" in line or "via" in line:
                    route["Next-Hop"] = line[:line.find(",")]
                    # if this is a local route (IP is configured on this device)
                    if route["Process"] == "local":
                        route["Next-Hop"] = "None"
                    # if the IP is routed by this device
                    elif route["Process"] == "connected":
                        route["Next-Hop"] = address
                    # if this is a ultimate route (has a exit interface)
                    if "via" in line:
                        routeWords = line.split(" ")
                        for i in range(len(routeWords)):
                            if routeWords[i] == "via":
                                route["Interface"] = routeWords[i+1].replace(",","")
                        # if this is an aggregate route
                        if route["Interface"][0:4] == "Null":
                            route["Next-Hop"] = "None"
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
                    network = ps.returnN(line, 3)
                    route["Network"] = network
                elif "Known via" in line:
                    # determine the process the route was learned through
                    line = line[line.find("\"")+1:]
                    process = line[:line.find("\"")]
                    route["Process"] = process
                elif "Routing Descriptor Blocks" in line:
                    # if the section containing the next hop will start next line
                    routeBlock = True
    else:
        cmd = "show route "+address
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # loop over the output
        routeBlock = False
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if routeBlock:
                # if this is the selected route
                if "from" in line or "via" in line:
                    route["Next-Hop"] = ps.returnN(line, 0).replace(",","")
                    # if this is a local route (IP is configured on this device)
                    if route["Process"] == "local":
                        route["Next-Hop"] = "None"
                    # if the IP is routed by this device
                    elif route["Process"] == "connected":
                        route["Next-Hop"] = address
                    # if this is a ultimate route (has a exit interface)
                    if "via" in line:
                        port = ps.returnN(line, len(line.split(" "))-1)
                        route["Interface"] = port
                        # if this is an aggregate route
                        if port[0:4] == "Null":
                            route["Next-Hop"] = "None"
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
import cisco_asr9k as asr9k

def get_ips(device):
    # same as Cisco ASR9K
    return asr9k.get_ips(device)

def get_interfaces(device):
    # same as Cisco ASR9K
    return asr9k.get_interfaces(device)

def get_MACs(device):
    # same as Cisco ASR9K
    return asr9k.get_MACs(device)

def get_ARPs(device):
    # same as Cisco ASR9K
    return asr9k.get_ARPs(device)

def get_route(device, address):
    # same as Cisco ASR9K
    return asr9k.get_route(device, address)

