#!/usr/bin/python3.6

import re
import networking as n
import cisco_ios as ios

def get_interfaces(device):
    return ios.get_interfaces(device)

def get_ips(device):
    return ios.get_ips(device)

def get_arps(device):
    return ios.get_arps(device)

def get_macs(device):
    macs = ios.get_macs(device)
    if device.model != 'CBR8':
        return macs
    # if this is a CBR8
    else:
        ignore_macs = ['ffff.ffff.ffff']
        # get CM MACs
        cmd = "show cable modem"
        device.get_response(cmd)
        matches = re.finditer(r"(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+((\d{1,3}\.){3}\d{1,3}|-+)[ ]+C(?P<interface>\d+/\d+/\d+)/", device.response, re.M)
        for match in matches:
            macs.append({'interface': 'Cable'+match.group('interface'), 'mac': match.group('mac')})
        # get all other MACs from ARPs
        arps = get_arps(device)
        for arp in arps:
            missing = True
            for mac in macs:
                if arp['mac'] == mac['mac']:
                    missing = False
                    break
            if missing:
                macs.append({'interface': arp['interface'], 'mac': arp['mac']})
    return macs

def get_route(device, address):
    return ios.get_route(device, address)

