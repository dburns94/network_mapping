#!/usr/bin/python3.6

import sys
import networking as n
import pexpect_ext as p_ext
import parseString as ps
import re_ext

def noPaging(session, expec):
  pass

# device info gathering
def getHostname(session, cmd):
  hostname = ""
  lines = p_ext.sendCMD(session, cmd, ".*#", 5)
  for i in lines:
    if "#" in i:
      hostname = i[i.find(":")+1:i.find("#")-1]
  return hostname

def getSwVersion(session, expec):
  version = "Unknown"
  cmd = "show software-mngt oswp | match exact:\" active\""
  output = p_ext.getOutput(session, cmd, expec, 10)
  pattern = r"^\d+[ ]+(\S+)"
  match = re_ext.getMatch(output, pattern)
  if match != None:
    version = match.group(1)
  return version

###################################################################################
## Global
###################################################################################

# initial SG info gathering
def getMacs(session, expec):
  macs = []
  # get interfaces
  interfaces = []
  cmd = "info configure cmts interface | match exact:create"
  output = p_ext.getOutput(session, cmd, expec, 10)
  pattern = r"interface (?P<name>(\d{1,2}/){3}\d{1,2})"
  matches = re_ext.getMatches(output, pattern)
  for match in matches:
    interface = match.group("name")
    if interface not in interfaces:
      interfaces.append(interface)
  # check if each interface is up
  for interface in interfaces:
    cmd = "show interface cable %s | match exact:up" % interface
    output = p_ext.getOutput(session, cmd, expec, 10)
    pattern = r"(\d{1,2}/){3}\d{1,2} is up"
    match = re_ext.getMatch(output, pattern)
    if match != None and interface not in macs:
      macs.append(interface)
  return macs

def getDescription(session, expec, mac):
  description = "None Found"
  cmd = "info configure cmts interface " + mac
  output = p_ext.getOutput(session, cmd, expec, 10)
  pattern = r"alias[ ]+(\S+)"
  match = re_ext.getMatch(output, pattern)
  if match != None:
    description = match.group(1)
  return description

def getDSUS(session, expec, mac):
  DS = mac
  US = mac
  return [DS, US]

def getIPinterface(session, expec, mac):
  ipInterface = "0"
  cmd = "info configure cmts interface " + mac
  output = p_ext.getOutput(session, cmd, expec, 10)
  pattern = r"bundle (\d{1,3})"
  match = re_ext.getMatch(output, pattern)
  if match != None:
    ipInterface = "bundle "+match.group(1)
  return ipInterface

def cmCountTotal(session, expec):
  count = {'online': 0, 'total': 0}
  cmd = "show cable modem total summary | match exact:Total"
  output = p_ext.getOutput(session, cmd, expec, 10)
  pattern = r"^Total:[ ]+(\d+)[ ]+(\d+)"
  match = re_ext.getMatch(output, pattern)
  if match != None:
    count['total'] = match.group(1)
    count['online'] = match.group(2)
  return count

# cmts-status info gathering
def ipConnectivity(device, ips, iphelper):
    pings = []
    # for each IP
    for ip in ips:
        sys.stdout.write('.')
        # send pings
        cmd = f"ping {iphelper} source {ip['address'].split('/')[0]} rapid"
        device.get_response(cmd)
        # get the pings counts
        match = re.search(r"^(?P<sent>\d+)[ ]+packets transmitted, (?P<received>\d+) packets received", device.response, re.M)
        if match is not None:
            pings.append({'ip': ip['address'], 'recieved': match.group('received'), 'transmitted': match.group('sent')})
    return pings

def channelStatus(device, mac):
    ds_status = []
    us_status = []
    # get interface power-levels output
    if getattr(device, 'mac_interface_status', None) is None:
        cmd = "show interface dpoe downstream"
        device.mac_interface_status = device.get_response(cmd)
    # get interface status
    cmd = f"show interface cable {mac} downstream"
    device.get_response(cmd)
    # get the status
    match = re.search(r"^"+mac+r" is (?P<status>[\S ]+)", device.response, re.M)
    if match is None:
        return ds_status, us_status
    sys.stdout.write('.')
    status = match.group('status').replace('administratively','admin')
    # get the power level
    power = '-'
    match = re.search(r"^"+mac+r"[ ]+(?P<power>(-)?\d+\.\d+)[ ]+", device.mac_interface_status, re.M)
    if match is not None:
        power = match.group('power')
    ds_status.append({'channel': mac, 'status': status, 'frequency': '-', 'power': power})
    return ds_status, us_status

def cmCount(device, mac):
    counts = {'online': 0, 'total': 0}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the cable-mac number
    number = None
    match = re.search(r"(\d+/){3}\d+", mac)
    if match is not None:
        number = match.group(0)
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^"+number+r"[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<unregistered>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
        if match is not None:
            counts['total'] = int(match.group('total'))
            counts['online'] = int(match.group('registered'))
    return counts

##### TEMP #####
def getAllIPs(session, expec):
    ipv4 = []
    ipv6 = []
    cmd = "admin display-config"
    output = p_ext.getOutput(session, cmd, expec, 20)
    # get interfaces
    matches = re.finditer(r"^(?P<spaces>[ ]+)interface \"(?P<interface>\S+)\".*\n"+
                          r"((?P=spaces)[ ]+.*\n)+", output, re.M)
    # for each interface
    for match in matches:
        interface_config = match.group(0)
        # look for IPs in the interface config
        addresses = re.finditer(r"^[ ]+(address|secondary)[ ]+(?P<ip>[\d./]+)", interface_config, re.M)
        for address in addresses:
            ip = n.IP(address.group('ip'))
            if ip.valid:
                # add IPv4 data to address list
                ipv4.append({'Interface': match.group('interface'), 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    return [ipv4, ipv6]

###############
##### NEW #####
###############
import re

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show software-mngt oswp"
    device.get_response(cmd)
    print(device.response)
    # parse the response
    match = re.search(r"^\d+[ ]+(?P<version>\S+)[ ]+\S+[ ]+active[ ]+", device.response, re.M)
    if match is not None:
        version = match.group('version').strip()
    return version

############################################################
############### Networking #################################
############################################################
def get_ips(device):
    ipv4 = []
    ipv6 = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get bundle interfaces
    matches = re.finditer(r"^    (?P<interface>bundle \d+) vcm-oam-vlan (?P<vlan>\d+) create.*\n", device.config, re.M)
    for match in matches:
        interface = match.group('interface')
        # get the VLAN configs
        match = re.search(r"^            interface \".*\" create.*\n"+
                          r"(                .+\n)*"+
                          r"                sap nt:vp:\d+:"+match.group('vlan')+r" create.*\n"+
                          r"(                .+\n)*", device.config, re.M)
        if match is not None:
            bundle_config = match.group(0)
            # get IPv4 addresses
            ip_matches = re.finditer(r"^                (address|secondary) (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", bundle_config, re.M)
            for ip_match in ip_matches:
                # get the IP address
                ip = n.IP(ip_match.group('ip'))
                # if this is a valid IP address
                if ip.valid:
                    # add IPv4 data to address list
                    #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
                    ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get routing section
    match = re.search(r"^    router Base\n"+
                      r"(        .+\n)*", device.config, re.M)
    if match is None:
        return ipv4, ipv6
    # get loopback and WAN interfaces
    matches = re.finditer(r"^        interface \"(?P<interface>\S+)\"\n"+
                          r"(            .+\n)+", match.group(0), re.M)
    for match in matches:
        interface = match.group('interface')
        # get IPv4 address
        ip_match = re.search(r"^            address (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", match.group(0), re.M)
        if ip_match is not None:
            # get the IP address
            ip = n.IP(ip_match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv4 data to address list
                #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
                ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get interfaces
#    matches = re.finditer(r"^(?P<spaces>[ ]+)interface \"(?P<interface>\S+)\".*\n"+
 #                         r"((?P=spaces)[ ]+.*\n)+", device.config, re.M)
  #  # for each interface
   # for match in matches:
    #    interface_config = match.group(0)
     #   # look for IPs in the interface config
      #  addresses = re.finditer(r"^[ ]+(address|secondary)[ ]+(?P<ip>[\d./]+)", interface_config, re.M)
       # for address in addresses:
        #    ip = n.IP(address.group('ip'))
         #   if ip.valid:
          #      # add IPv4 data to address list
           #     ipv4.append({'Interface': match.group('interface'), 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    return ipv4, ipv6

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
    matches = re.finditer(r"^\d+/\d+/\d+/\d+[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)", device.response, re.M)
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
    matches = re.finditer(r"^    interface (?P<mac>(\d+/){3}\d+) create.*\n", device.config, re.M)
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
    match = re.search(r"^    interface "+mac+r" create.*\n"+
                      r"(        .+\n)*"+
                      r"        alias (?P<description>[\S ]+)", device.config, re.M)
    if match is not None:
        print(match.group(0))
        description = match.group('description').strip()
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    match = re.search("(\d+/){3}\d+", mac)
    if match is not None:
        DS = match.group(0)
        US = match.group(0)
    return DS, US

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    match = re.search("(\d+/){3}\d+", mac)
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
    match = re.search(r"(\d+/){3}\d+", mac)
    if match is not None:
        number = match.group(0)
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^"+number+r"[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<unregistered>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
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
    match = re.search(r"^    interface "+mac+r" create.*\n"+
                      r"(        .+\n)*"+
                      r"        bundle (?P<interface>\d+)", device.config, re.M)
    if match is not None:
        interface = f"bundle {match.group('interface')}"
    return interface

def get_mac_IPs(device, interface):
    ipv4 = []
    ipv6 = []
    ipv4helper = []
    ipv6helper = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get ip-bundle config
    match = re.search(r"^    "+interface+r" vcm-oam-vlan (?P<vlan>\d+) create.*\n", device.config, re.M)
    if match is not None:
        # get the VLAN configs
        match = re.search(r"^            interface \".*\" create.*\n"+
                          r"(                .+\n)*"+
                          r"                sap nt:vp:\d+:"+match.group('vlan')+r" create.*\n"+
                          r"(                .+\n)*", device.config, re.M)
        if match is not None:
            bundle_config = match.group(0)
            # get IPv4 addresses
            matches = re.finditer(r"^                (address|secondary) (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", bundle_config, re.M)
            for match in matches:
                ip = n.IP(match.group('ip'))
                if ip.valid:
                    ipv4.append({'interface': interface, 'address': str(ip)})
            # get IPv4 helpers
            matches = re.finditer(r"^                    server (?P<ip>(\d{1,3}\.){3}\d{1,3})", bundle_config, re.M)
            for match in matches:
                ip = n.IP(match.group('ip'))
                if ip.valid and ip.addr not in ipv4helper:
                    ipv4helper.append(ip.addr)
    return ipv4, ipv4helper, ipv6, ipv6helper

############################################################
############### CM #########################################
############################################################
def get_modem(device, modem, query_value, query_type):
    # declare command set
    cmd_sets = {
                'MAC':  [
                         f'show cable modem {query_value}',
                         f'show cable modem cpe {query_value}'
                        ],
                'IPv4': [
                         f'show cable modem {query_value}',
                         f'show cable modem cpe | match exact:{query_value}'
                        ],
                'IPv6': [
                         f'show cable modem {query_value}',
                         f'show cable modem cpe | match exact:{query_value}'
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
        match = re.search(r"^(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<ip>((\d{1,3}\.){3}\d{1,3}))[ ]+"+
                          r"(\d{1,2}/){3}\d{1,2}[ ]+(?P<state>\S+)[ ]+\d+[ ]+", device.response, re.M)
        if match is not None:
            modem.output = device.response
            modem.mac = match.group('mac')
            modem.state = match.group('state')
            if 'offline' not in modem.state.lower():
                modem.offline = False
            else:
                modem.offline = True
            ip = match.group('ip')
            if ip != '0.0.0.0':
                modem.ipv4 = ip
            break
#    if match is None:
 #       modem.output = modem.output[1:]
    return modem

