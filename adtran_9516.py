#!/usr/bin/python3.6

import sys
import networking as n
import pexpect_ext as p_ext
import parseString as ps
import re_ext

def noPaging(session, expec):
  cmd = "terminal length 0"
  p_ext.sendCMD(session, cmd, expec, 10)

def getSwVersion(session, expec):
  version = "Unknown"
  cmd = "show version | include image"
  output = p_ext.getOutput(session, cmd, expec, 10)
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
    # same as ADTRAN 9504N
    return a9504N.ipConnectivity(device, ips, iphelper)

def channelStatus(device, mac, DS, US):
    # same as ADTRAN 9504N
    return a9504N.channelStatus(device, mac, DS, US)

def cmCount(device, mac):
    # same as ADTRAN 9504N
    return a9504N.cmCount(device, mac)

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
  output = p_ext.getOutput(session, cmd, expec, 10)
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

def cmCountTotal(session, expec):
  count = {'online': 0, 'total': 0}
  cmd = "show cable modem summary total | include Total"
  output = p_ext.getOutput(session, cmd, expec, 10)
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
import adtran_9504N as a9504N
import casa_c100g as c100g

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show version | include image"
    device.get_response(cmd)
    # parse the response
    match = re.search(r"^System image file is \".*(?P<version>dpoe\S+)\"", device.response, re.M)
    if match is not None:
        version = match.group('version').strip().upper()
    return version

############################################################
############### Networking #################################
############################################################
def get_ips(device):
  # same as Cisco 9500
  return a9504N.get_ips(device)

def get_route(device, address):
  # same as CASA C100G
  return c100g.get_route(device, address)

############################################################
############### DOCSIS #####################################
############################################################
## Chassis
def get_total_cm_count(device):
    # same as ADTRAN 9504N
    return a9504N.get_total_cm_count(device)

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
    # same as ADTRAN 9504N
    return a9504N.get_modem(device, modem, query_value, query_type)

