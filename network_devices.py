#!/usr/bin/python3.6

import networking as n
import rethinkdb as rdb
import rethinkdb_ext as r_ext

def findRouter(dbDatabase, dbTable, hostnames, address):
## hostnames is the list of routers already checked for a route
    hostData = {"Host": "Unknown"}
    if address is None:
        return hostData["Host"]
    # if the address is an IPv6 address
    if ":" in address:
        # search the database for a device with the same link-local IP
        data = r_ext.getData(dbDatabase, dbTable, dataFilter={"Link-Local": address})
        # if results were found
        if len(data) > 0:
            hostData = data[0]
        else:
            # convert IPv6 address to decimal
            decIP = n.v6_dec(address)
            # search database for a network containing the IPv6 address
            data = r_ext.getIPrange(dbDatabase, dbTable, decIP)
            # if any networks were found
            if len(data) > 0:
                # if more than 1 network was found
                if len(data) > 1:
                    # loop over the networks found
                    for network in data:
                        # if the IP searched is assigned to the router of the network
                        if address.split("/")[0] == network["Assigned"]:
                            # save the network
                            hostData = network
                            break
                    # if no network was found
                    if hostData["Host"] == "Unknown":
                        # loop over the networks found
                        for network in data:
                            # if the hostname is not in the list of routers already check
                            if network["Host"] not in hostnames:
                                # save the network
                                hostData = network
                                break
                # if only 1 network was found
                else:
                    hostData = data[0]
    # if the address is an IPv4 address
    else:
        # convert IPv4 address to decimal
        decIP = n.v4_dec(address)
        # search database for a network containing the IPv4 address
        data = r_ext.getIPrange(dbDatabase, dbTable, decIP)
        # if any networks were found
        if len(data) > 0:
            # if more than 1 network was found
            if len(data) > 1:
                # loop over the networks found
                for network in data:
                    # if the IP searched is assigned to the router of the network
                    if address.split("/")[0] == network["Assigned"]:
                        # save the network
                        hostData = network
                        break
                    # if no network was found
                    if hostData["Host"] == "Unknown":
                        # get the most specific network
                        prefix = -1
                        # loop over the networks found
                        for network in data:
                            # if this is more specific network, use it
                            this_prefix = int(network["Network"].split("/")[1])
                            if this_prefix > prefix:
                                prefix = this_prefix
                                hostData = network
            # if only 1 network was found
            else:
                if data[0]["Host"] not in hostnames:
                    hostData = data[0]
    return hostData["Host"]

def findDeviceInfo(dbDatabase, dbTable, hostname):
    # get host information
    data = r_ext.getData(dbDatabase, dbTable, dataFilter={"hostname": hostname})
    # if results were found
    if len(data) > 0:
        return data[0]
    else:
        return False

import cisco_4500 as c4500
import cisco_3850 as c3850
import cisco_9500 as c9500
import cisco_asr9k as asr9k
import cisco_crsx as crsx
import arris_e6000 as e6000
import casa_c100g as c100g
import cisco_cbr8 as cbr8
import adtran_9504N as a9504N
import adtran_9516 as a9516
import nokia_7360 as n7360
#import nokia_sc2d as sc2d
import nokia_gac as gac

def noPaging(session, expec, deviceType):
    if deviceType == "4500":
        c4500.noPaging(session, expec)
    elif deviceType == "3850":
        c3850.noPaging(session, expec)
    elif deviceType == "9500":
        c9500.noPaging(session, expec)
    elif deviceType == "ASR9K":
        asr9k.noPaging(session, expec)
    elif deviceType == "CRS-X":
        crsx.noPaging(session, expec)
    elif deviceType == "E6000":
        e6000.noPaging(session, expec)
    elif deviceType == "C100G":
        c100g.noPaging(session, expec)
    elif deviceType == "CBR8":
        cbr8.noPaging(session, expec)
    elif deviceType == "9504N":
        a9504N.noPaging(session, expec)
    elif deviceType == "9516":
        a9516.noPaging(session, expec)

def getSwVersion(session, expec, deviceType):
    if deviceType == "4500":
        version = c4500.getSwVersion(session, expec)
    elif deviceType == "3850":
        version = c3850.getSwVersion(session, expec)
    elif deviceType == "9500":
        version = c9500.getSwVersion(session, expec)
    elif deviceType == "ASR9K":
        version = asr9k.getSwVersion(session, expec)
    elif deviceType == "CRS-X":
        version = crsx.getSwVersion(session, expec)
    return version

def getSN(session, expec, deviceType):
    if deviceType == "4500":
        sn = c4500.getSN(session, expec)
    elif deviceType == "3850":
        sn = c3850.getSN(session, expec)
    elif deviceType == "9500":
        sn = c9500.getSN(session, expec)
    elif deviceType == "ASR9K":
        sn = asr9k.getSN(session, expec)
    elif deviceType == "CRS-X":
        sn = crsx.getSN(session, expec)
    return sn

def getAllIPs(session, expec, deviceType):
    if deviceType == "4500":
        [ipv4, ipv6] = c4500.getAllIPs(session, expec)
    elif deviceType == "3850":
        [ipv4, ipv6] = c3850.getAllIPs(session, expec)
    elif deviceType == "9500":
        [ipv4, ipv6] = c9500.getAllIPs(session, expec)
    elif deviceType == "ASR9K":
        [ipv4, ipv6] = asr9k.getAllIPs(session, expec)
    elif deviceType == "CRS-X":
        [ipv4, ipv6] = crsx.getAllIPs(session, expec)
    elif deviceType == "E6000":
        [ipv4, ipv6] = e6000.getAllIPs(session, expec)
    elif deviceType == "C100G":
        [ipv4, ipv6] = c100g.getAllIPs(session, expec)
    elif deviceType == "CBR8":
        [ipv4, ipv6] = cbr8.getAllIPs(session, expec)
    elif deviceType == "9504N":
        [ipv4, ipv6] = a9504N.getAllIPs(session, expec)
    elif deviceType == "9516":
        [ipv4, ipv6] = a9516.getAllIPs(session, expec)
    elif deviceType == "7360":
        [ipv4, ipv6] = n7360.getAllIPs(session, expec)
    return [ipv4, ipv6]

def getInterfaces(session, expec, deviceType):
    if deviceType == "4500":
        interfaces = c4500.getInterfaces(session, expec)
    elif deviceType == "3850":
        interfaces = c3850.getInterfaces(session, expec)
    elif deviceType == "9500":
        interfaces = c9500.getInterfaces(session, expec)
    elif deviceType == "ASR9K":
        interfaces = asr9k.getInterfaces(session, expec)
    elif deviceType == "CRS-X":
        interfaces = crsx.getInterfaces(session, expec)
    return interfaces

def getMACs(session, expec, deviceType):
    if deviceType == "4500":
        macs = c4500.getMACs(session, expec)
    elif deviceType == "3850":
        macs = c3850.getMACs(session, expec)
    elif deviceType == "9500":
        macs = c9500.getMACs(session, expec)
    elif deviceType == "ASR9K":
        macs = asr9k.getMACs(session, expec)
    elif deviceType == "CRS-X":
        macs = crsx.getMACs(session, expec)
    return macs

def getARPs(session, expec, deviceType):
    if deviceType == "4500":
        arps = c4500.getARPs(session, expec)
    elif deviceType == "3850":
        arps = c3850.getARPs(session, expec)
    elif deviceType == "9500":
        arps = c9500.getARPs(session, expec)
    elif deviceType == "ASR9K":
        arps = asr9k.getARPs(session, expec)
    elif deviceType == "CRS-X":
        arps = crsx.getARPs(session, expec)
    return arps

def getInterfaceRates(session, expec, deviceType):
    if deviceType == "4500":
        interfaces = c4500.getInterfaceRates(session, expec)
    elif deviceType == "3850":
        interfaces = c3850.getInterfaceRates(session, expec)
    elif deviceType == "9500":
        interfaces = c9500.getInterfaceRates(session, expec)
    elif deviceType == "ASR9K":
        interfaces = asr9k.getInterfaceRates(session, expec)
    elif deviceType == "CRS-X":
        interfaces = crsx.getInterfaceRates(session, expec)
    return interfaces

def getRoute(session, expec, address, deviceType):
    address = address.lower()
    if deviceType == "4500":
        route = c4500.getRoute(session, expec, address)
    elif deviceType == "3850":
        route = c3850.getRoute(session, expec, address)
    elif deviceType == "9500":
        route = c9500.getRoute(session, expec, address)
    elif deviceType == "ASR9K":
        route = asr9k.getRoute(session, expec, address)
    elif deviceType == "CRS-X":
        route = crsx.getRoute(session, expec, address)
    elif deviceType == "E6000":
        route = e6000.getRoute(session, expec, address)
    elif deviceType == "C100G":
        route = c100g.getRoute(session, expec, address)
    elif deviceType == "CBR8":
        route = cbr8.getRoute(session, expec, address)
    elif deviceType == "9504N":
        route = a9504N.getRoute(session, expec, address)
    elif deviceType == "9516":
        route = a9516.getRoute(session, expec, address)
    else:
        route = {"Next-Hop": "Not Supported"}
    return route

###############
##### NEW #####
###############
def get_ips(device):
    ipv4 = []
    ipv6 = []
    if device.model == '4500':
        ipv4, ipv6 = c4500.get_ips(device)
    elif device.model == '3850':
        ipv4, ipv6 = c3850.get_ips(device)
    elif device.model == '9500':
        ipv4, ipv6 = c9500.get_ips(device)
    elif device.model == 'ASR9K':
        ipv4, ipv6 = asr9k.get_ips(device)
    elif device.model == 'CRS-X':
        ipv4, ipv6 = crsx.get_ips(device)
    elif device.model == 'E6000':
        ipv4, ipv6 = e6000.get_ips(device)
    elif device.model == 'C100G':
        ipv4, ipv6 = c100g.get_ips(device)
    elif device.model == 'CBR8':
        ipv4, ipv6 = cbr8.get_ips(device)
    elif device.model == '9504N':
        ipv4, ipv6 = a9504N.get_ips(device)
    elif device.model == '9516':
        ipv4, ipv6 = a9516.get_ips(device)
    elif device.model == '7360':
        ipv4, ipv6 = n7360.get_ips(device)
    elif device.model == 'GAC':
        ipv4, ipv6 = gac.get_ips(device)
    return ipv4, ipv6

def get_interfaces(device):
    interfaces = []
    if device.model == '4500':
        interfaces = c4500.get_interfaces(device)
    elif device.model == '3850':
        interfaces = c3850.get_interfaces(device)
    elif device.model == '9500':
        interfaces = c9500.get_interfaces(device)
    elif device.model == 'ASR9K':
        interfaces = asr9k.get_interfaces(device)
    elif device.model == 'CRS-X':
        interfaces = crsx.get_interfaces(device)
    return interfaces

def get_MACs(device):
    macs = []
    if device.model == '4500':
        macs = c4500.get_MACs(device)
    elif device.model == '3850':
        macs = c3850.get_MACs(device)
    elif device.model == '9500':
        macs = c9500.get_MACs(device)
    elif device.model == 'ASR9K':
        macs = asr9k.get_MACs(device)
    elif device.model == 'CRS-X':
        macs = crsx.get_MACs(device)
    return macs

def get_ARPs(device):
    arps = []
    if device.model == '4500':
        arps = c4500.get_ARPs(device)
    elif device.model == '3850':
        arps = c3850.get_ARPs(device)
    elif device.model == '9500':
        arps = c9500.get_ARPs(device)
    elif device.model == 'ASR9K':
        arps = asr9k.get_ARPs(device)
    elif device.model == 'CRS-X':
        arps = crsx.get_ARPs(device)
    return arps

def get_route(device, address):
    route = {'Next-Hop': 'Not Supported'}
    if not isinstance(address, n.IP):
        address = n.IP(address)
    if not address.valid:
        return route
    if device.model == '4500':
        route = c4500.get_route(device, address)
    elif device.model == '3850':
        route = c3850.get_route(device, address)
    elif device.model == '9500':
        route = c9500.get_route(device, address)
    elif device.model == 'ASR9K':
        route = asr9k.get_route(device, address)
    elif device.model == 'CRS-X':
        route = crsx.get_route(device, address)
    elif device.model == 'E6000':
        route = e6000.get_route(device, address)
    elif device.model == 'C100G':
        route = c100g.get_route(device, address)
    elif device.model == 'CBR8':
        route = cbr8.get_route(device, address)
    elif device.model == '9504N':
        route = a9504N.get_route(device, address)
    elif device.model == '9516':
        route = a9516.get_route(device, address)
    return route

############################################################
############### Status Checks ##############################
############################################################
def get_all_mcounts(device):
    mcounts = []
    if device.model == '9500':
        mcounts = c9500.get_all_mcounts(device)
    elif device.model == '4500':
        mcounts = c4500.get_all_mcounts(device)
    elif device.model == '3850':
        mcounts = c3850.get_all_mcounts(device)
    return mcounts

def get_all_interface_states(device):
    interfaces = []
    if device.model == '9500':
        interfaces = c9500.get_all_interface_states(device)
    elif device.model == '4500':
        interfaces = c4500.get_all_interface_states(device)
    elif device.model == '3850':
        interfaces = c3850.get_all_interface_states(device)
    return interfaces

def get_ipv4_states(device, dest='172.30.86.61'):
    interfaces = []
    if device.model == '9500':
        interfaces = c9500.get_ipv4_states(device, dest)
    elif device.model == '4500':
        interfaces = c4500.get_ipv4_states(device, dest)
    elif device.model == '3850':
        interfaces = c3850.get_ipv4_states(device, dest)
    return interfaces

def get_ipv6_states(device, dest='2001:1998:2e0:40::2'):
    interfaces = []
    if device.model == '9500':
        interfaces = c9500.get_ipv6_states(device, dest)
    elif device.model == '4500':
        interfaces = c4500.get_ipv6_states(device, dest)
    elif device.model == '3850':
        interfaces = c3850.get_ipv6_states(device, dest)
    return interfaces

