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
    cmd = "show arp"
    device.get_response(cmd)
    matches = re.finditer(r"^Internet[ ]+(?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+(?P<interface>[\w\-.]+)", device.response, re.M)
    for match in matches:
        arps.append({'interface': match.group('interface'), 'ip': match.group('ip'), 'mac': match.group('mac')})
    return arps

def get_macs(device):
    macs = []
    # get MAC address table
    cmd = "show mac-address-table"
    device.get_response(cmd)
    #print(device.response)
    matches = re.finditer(r"[ ]*\d+[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+\w+[ ]+\S+[ ]+(?P<interface>[\w/\-.]+)", device.response)
    for match in matches:
        macs.append({'interface': match.group('interface'), 'mac': match.group('mac')})
    return macs

