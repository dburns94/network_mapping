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
            version = line[:line.find(" ")]
    return version

def getSN(session, expec):
    sn = ["", ""]
    cmd = "show version | include System Serial Number"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[1:-1]:
        line = line[line.find(":")+2:]
        if len(sn[0]) == 0:
            sn[0] = line
        else:
            sn[1] = line
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
        # # change port nomenclature
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
                # collect interface Vlan
                interfaces[i]["Vlan"] = row[col["Vlan"]]
                break
    return interfaces

def getMACs(session, expec):
    macs = []
    # get MAC address table
    cmd = "show mac address-table | exclude CPU|Total|Table|------"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # format lines as a table
    [col, table] = ps.parseTable(lines[2:-2])
    # loop over table
    for row in table[1:]:
        # change port nomenclature
        port = row[col["Ports"]]
        port = port.replace("Vl", "Vlan")
        # collect MAC addresses
        macs.append({"MAC": row[col["Mac Address"]], "Interface": port, "Type": row[col["Type"]].lower(), "Time": int(time.time())})
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
        # collect ARPs
        arps.append({"Address": row[col["Address"]], "MAC": row[col["Hardware Addr"]], "Interface": row[col["Interface"]], "Type": arpType, "Time": int(time.time())})
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
        port = port.replace("GigabitEthernet", "Gi")
        # collect transmit and receive rate in bits/sec
        trans = int(row[col["TXBS"]])
        rec = int(row[col["RXBS"]])
        interfaces.append({"Interface": port, "Transmit": trans, "Recieve": rec})
    return interfaces

###############
##### NEW #####
###############
import re
import cisco_9500 as c9500

def get_ips(device):
    # same as Cisco 9500
    return c9500.get_ips(device)

def get_interfaces(device):
    # same as Cisco 9500
    return c9500.get_interfaces(device)

def get_MACs(device):
    # same as Cisco 9500
    return c9500.get_MACs(device)

def get_ARPs(device):
    # same as Cisco 9500
    return c9500.get_ARPs(device)

def get_route(device, address):
    # same as Cisco 9500
    return c9500.get_route(device, address)

