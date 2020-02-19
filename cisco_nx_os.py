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
    # get ARP entires
    cmd = "show ip arp"
    device.get_response(cmd)
    matches = re.finditer(r"^(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+((\d{2}:){2}\d{2}|-)[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<interface>[\w/\-.]+)", device.response, re.M)
    for match in matches:
        arps.append({'interface': match.group('interface'), 'ip': match.group('ip'), 'mac': match.group('mac')})
    return arps

#def get_macs(device):
 #   return ios.get_macs(device)

def get_macs(device):
    macs = []
    # get MAC address table
    cmd = "show mac address-table"
    device.get_response(cmd)
    #print(device.response)
    matches = re.finditer(r"(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+[\d~]+[ ]+\w+[ ]+\w+[ ]+(?P<interface>[\w/\-.]+)", device.response)
    for match in matches:
        macs.append({'interface': match.group('interface'), 'mac': match.group('mac')})
    return macs

def get_route(device, address):
    return ios.get_route(device, address)

