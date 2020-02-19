#!/usr/bin/python3.6

import sys
import networking as n
import pexpect_ext as p_ext
import parseString as ps
import re_ext

###################################################################################
## CM
###################################################################################

def isDeviceOnline(session, expec, queryValue, queryType):
    online = False
    cm_mac = ""
    # declare command set
    cmd_set = {"MAC":  ["show cable modem "+queryValue+" | begin ^S/C/CH",
                                            "show cable modem cpe-mac "+queryValue+" | begin ^S/C/CH"
                                          ],
                          "IPv4": ["show cable modem "+queryValue+" | begin ^S/C/CH",
                                            "show cable modem cpe-ip "+queryValue+" | begin ^S/C/CH"
                                          ],
                          "IPv6": ["show cable modem cm-ipv6 "+queryValue+" | begin ^S/C/CH",
                                            "show cable modem cpe-ipv6 "+queryValue+" | begin ^S/C/CH"
                                          ]
                        }
    # declare set of valid CM states
    states = ["operational", "rang", "online-d", "denied",
                        "dhcpv", "register", "tftp", "eaestart",
                        "frwddisable", "regbpiinit", "rfmuteall", "rngaborted"]
    # send commands
    for cmd in cmd_set[queryType]:
        output = []
        # execute the command
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # for each line in the output
        for line in lines[1:-1]:
            # keep the output for later use
            output.append(line)
            # make the line lowercase
            line = line.lower()
            # for each valid CM state
            for state in states:
                # if the modem is in that state
                if state in line:
                    # the modem is online (not offline)
                    online = True
                    # stop checking
                    break
            # if modem was found online
            if online:
                # stop checking
                break
        # if modem was found online
        if online:
            # stop checking
            break
    # if modem was found online
    if online:
        # parse the output as a table
        [col, table] = ps.parseTable(output)
        # if the table has a MAC address column
        if col.get("MAC address") != None:
            # for each row in the table
            for row in table[1:]:
                # get the value in the MAC address column
                mac = row[col["MAC address"]]
                # if this was a valid MAC address
                if n.validMAC(mac):
                    # store the MAC as the CM MAC
                    cm_mac = mac
                    break
    return [online, cm_mac]

def getCM_phy(session, expec, cm_mac):
    phy = {"US SNR": "", "DS SNR": "", "US Power TX": "", "US Power RX": "", "DS Power": ""}
    associations = {"US SNR": "USSNR", "DS SNR": "DSSNR", "US Power TX": "USPwr", "US Power RX": "USPwrRX", "DS Power": "DSPwr"}
    # send command
    cmd = "show cable modem "+cm_mac+" phy | begin ^\(DS-US\)"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # only keep the output needed
    output = []
    for line in lines[1:-1]:
        if "USPwr" in line:
            start = line.find("USPwr")
            end = start + 5
            line = line[:start]+"USPwrRX"+line[end:]
        if len(line) < 3:
            break
        elif "(dB" not in line:
            output.append(line)
    # parse the output as a table
    [col, table] = ps.parseTable(output)
    # add the data that is present
    for key, value in associations.items():
        if col.get(value) != None:
            phy[key] = table[1][col[value]]
    return phy

def getCM_ip(session, expec, cm_mac):
    cm_ip = ""
    # send command
    cmd = "show cable modem "+cm_mac+" | begin ^S/C/CH-S/CG/CH"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # only keep the output needed
    output = []
    for line in lines[1:-1]:
        if len(line) < 3:
            break
        elif "Offset" not in line:
            output.append(line)
    # parse the output as a table
    [col, table] = ps.parseTable(output)
    # if the table has a IP address column
    if col.get("IP Address") != None:
        # for each row in the table
        for row in table[1:]:
            # get the value in the MAC address column
            ip = row[col["IP Address"]]
            # if this was a valid MAC address
            if n.validIPv4(ip) or n.validIPv6(ip):
                # store the IP as the CM IP
                cm_ip = ip.lower()
                break
    return cm_ip

def getCM_macDomain(session, expec, cm_mac):
    cm_domain = ""
    # send command
    cmd = "show cable modem "+cm_mac+" | begin ^S/C/CH-S/CG/CH"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # only keep the output needed
    output = []
    for line in lines[1:-1]:
        if len(line) < 3:
            break
        elif "Offset" not in line:
            output.append(line)
    # parse the output as a table
    [col, table] = ps.parseTable(output)
    # if the table has a MAC domain column
    if col.get("Mac") != None:
        # get the value in the MAC domain column
        cm_domain = "cable-mac "+table[1][col["Mac"]]
    return cm_domain

def testPing(session, expec, ip, count, fail_threshold):
    success = True
    # initialize counts
    passed = 0
    failed = 0
    # create ping command
    if ":" in ip:
        cmd = "ping ipv6 "+ip+" repeat-count 1 timeout 1"
    else:
        cmd = "ping "+ip+" repeat-count 1 timeout 1"
    # for the number of pings
    for i in range(count):
        # send one ping
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # look at each line in the output
        for line in lines:
            # if this line contains the pings sent and recieved
            if "packets" in line:
                # parse out only the received
                piece = line.split(",")
                if len(piece) > 1:
                    result = piece[1].strip().split(" ")[0]
                    # if we recieved 1 ping back
                    if result == "1":
                        # the ping passed
                        passed += 1
                    # if we recieved 0 pings back
                    else:
                        # the ping failed
                        failed += 1
                break
        # if more pings failed than are allowd
        if failed > fail_threshold:
            # the ping test failed
            success = False
            # stop testing
            break
    # make sure the pings were successfully parsed
    if success:
        if passed < count-fail_threshold:
            success = False
    return success

###################################################################################
## Global
###################################################################################

def noPaging(session, expec):
    cmd = "terminal length 0"
    p_ext.sendCMD(session, cmd, expec, 10)

# device info gathering
def getHostname(session, cmd):
    hostname = ""
    lines = p_ext.sendCMD(session, cmd, ".*#", 5)
    for i in lines:
        if "#" in i:
            hostname = i[0:i.find("#"):1]
    return hostname

def getSwVersion(session, expec):
    version = "Unknown"
    cmd = "show image | include Version"
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    pattern = r"Version:[ ]+(\S+)"
    match = re_ext.getMatch(output, pattern)
    if match != None:
        version = match.group(1).replace("CER_V","")
    return version

def getGenType(session, expec):
    genType = "Gen1"
    cmd = "show linecard status"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[1:-1]:
        #if "DCAM2" in line or "UCAM2" in line:
        if "/RSM2" in line:
            genType = "Gen2"
            break
    return genType

# cmts-status info gathering
#def ipConnectivity(device, ips, iphelper):
 #   results = []
  #  ip_type = ''
   # for ip in ips:
    #    sys.stdout.write(".")
     #   # determine the IP type
      #  if ':' in ip:
       #     ip_type = 'ipv6 '
#        # get the response
 #       cmd = f"ping {ip_type}{iphelper} source {ip['address'].split('/')[0]}"
  #      device.get_response(cmd)
   #     # parse the response
    #    lines = device.response.split('\n')
     #   for i in lines[1:-1]:
      #      if "packets transmitted" in i:
       #         i = ps.minSpaces(i)
        #        recieved = int(ps.returnN(i,3))
         #       transmitted = int(ps.returnN(i,0))
          #      results.append({'ip': ip['address'], 'recieved': recieved, 'transmitted': transmitted})
#    return results

def ipConnectivity(device, ips, iphelper):
    pings = []
    # for each IP
    for ip in ips:
        sys.stdout.write('.')
        # determine the IP type
        ip_type = 'ipv6 ' if ':' in ip['address'] else ''
        # send pings
        cmd = f"ping {ip_type}{iphelper} source {ip['address'].split('/')[0]}"
        device.get_response(cmd, timeout=15)
        # get the pings counts
        match = re.search(r"^(?P<sent>\d+)[ ]+packets transmitted, (?P<received>\d+) packets received", device.response, re.M)
        if match is not None:
            pings.append({'ip': ip['address'], 'recieved': match.group('received'), 'transmitted': match.group('sent')})
    return pings

#def channelStatus(device, mac, DS, US):
 #   dsStatus = []
  #  usStatus = []
   # # get the response
    #cmd = "show interface " + mac
#    device.get_response(cmd)
 #   # parse the response
  #  lines = device.response.split('\n')
   # for i in lines[1:-1]:
    #    i = ps.minSpaces(i)
     #   if DS in i:
      #      sys.stdout.write('.')
       #     status = ps.returnN(i,4)
        #    if status != "IS" and status != "OOS":
         #       status = ps.returnN(i,3)
          #  try:
           #     power = str(float(ps.returnN(i,9))/10)
            #    if float(power) < 10:
             #       power = "-"
              #  else:
               #     power += " dBmV"
#            except:
 #               power = "-"
  #          dsStatus.append({'channel': ps.returnN(i,0), 'status': status, 'frequency': ps.returnN(i,6)[0:3]+" MHz", 'power': power})
   #     elif US in i:
    #        sys.stdout.write('.')
     #       frequency = ps.returnN(i,5).split("-")
      #      for f in range(len(frequency)):
       #         if len(frequency[f]) > 0:
        #            frequency[f] = str(float(frequency[f]))
         #   frequency = "-".join(frequency)
          #  usStatus.append({'channel': ps.returnN(i,0), 'status': ps.returnN(i,3), 'frequency': frequency+" MHz", 'power': '-'})
#    return [dsStatus, usStatus]

def channelStatus(device, mac, DS, US):
    ds_status = []
    us_status = []
    # get cable-macs output
    if getattr(device, 'mac_interface_status', None) is None:
        cmd = "show interface cable-mac"
        device.mac_interface_status = device.get_response(cmd)
    # determine the cable-mac
    cable_mac = r"\d+"
    match = re.search(r"\d+", mac)
    if match is not None:
        cable_mac = match.group(0)
    # get DOCSIS channels
    matches = re.finditer(r"^(?P<channel>"+DS+r"/\d{1,2})[ ]+\d+[ ]+\d+[ ]+\S+[ ]+(?P<status>\S+)[ ]+\S+[ ]+"+
                          r"(?P<freq>\d{3})0{6}[ ]+\d+[ ]+\S+[ ]+(?P<power>\d+)", device.mac_interface_status, re.M)
    for match in matches:
        sys.stdout.write('.')
        try:
            power = str(float(match.group('power'))/10)
        except:
            power = '-'
        ds_status.append({'channel': match.group('channel'), 'status': match.group('status'), 'frequency': match.group('freq'), 'power': power})
    # get OFDM channels
    matches = re.finditer(r"^(?P<channel>"+DS+r"/\d{1,2})[ ]+\d+[ ]+\d+[ ]+\S+[ ]+(?P<status>\S+)[ ]+"+
                          r"(?P<freq_start>\d+)\.\d+-(?P<freq_end>\d+)\.\d+[ ]+(?P<plc>\d+)[ ]+", device.mac_interface_status, re.M)
    for match in matches:
        sys.stdout.write('.')
        ds_status.append({'channel': match.group('channel'), 'status': match.group('status'), 'frequency': match.group('plc'), 'power': '-'})
    # get US channels
    matches = re.finditer(r"^(?P<channel>"+US+r"/\d{1,2})[ ]+"+cable_mac+r"[ ]+\d+[ ]+(?P<status>\S+)[ ]+\S+[ ]+"+
                          r"(?P<freq_start>\d+\.\d)\d+-(?P<freq_end>\d+\.\d)\d+[ ]+", device.mac_interface_status, re.M)
    for match in matches:
        sys.stdout.write('.')
        us_status.append({'channel': match.group('channel'), 'status': match.group('status'), 'frequency': f"{match.group('freq_start')}-{match.group('freq_end')}", 'power': '-'})
    return ds_status, us_status

#def getMCounts(device, multicasts):
 #   counts = []
  #  pattern = re_ext.compile(r"\((\d{1,3}\.){3}\d{1,3},\ (\d{1,3}\.){3}\d{1,3}\),\ packets:\ (?P<packets>\d+)")
   # for i in multicasts:
    #    sys.stdout.write('.')
     #   # get the response
      #  cmd = f"show ip mroute {i['multicast']} {i['source']} | include packets"
       # device.get_response(cmd)
        ## parse the response
#        match = pattern.search(device.response)
 #       if match is not None:
  #          counts.append({'multicast': {'multicast': i['multicast'], 'source': i['source']}, 'count': int(match.group("packets")), 'type': i['type'], 'tunnel': i['tunnel']})
   # return counts

def getMCounts(device, multicasts):
    counts = []
    # get multicast counts
    if getattr(device, 'mcounts', None) is None:
        device.get_mcounts()
    # for each multicast
    for mcast in multicasts:
        sys.stdout.write('.')
        # convert IPs to raw text
        src = mcast['source'].replace('.',r"\.")
        group = mcast['multicast']
        # get the packet count
        match = re.search(r"^\("+src+r", "+group+r"\), packets: (?P<packets>\d+)", device.mcounts, re.M)
        if match is not None:
            counts.append({'multicast': {'multicast': mcast['multicast'], 'source': mcast['source']}, 'count': int(match.group('packets')),
                           'type': mcast['type'], 'tunnel': mcast['tunnel']})
    return counts

#def getDSGcounts(device, DS, tunnels):
 #   count = []
  #  # get the response
   # cmd = f"show cable dsg counts {DS}/0"
    #device.get_response(cmd)
    # parse the response
#    pattern = re_ext.compile(r"^[ ]*(\d{1,2}/){2}\d{1,2}[ ]+(?P<tunnel>\d+)[ ]+\d+[ ]+(?P<packets>\d+)")
 #   matches = pattern.finditer(device.response)
  #  for match in matches:
   #     sys.stdout.write('.')
    #    count.append({"tunnel": match.group("tunnel"), "count": int(match.group("packets"))})
#    if len(count) == 0:
 #       count = []
  #      # get the response
   #     cmd = "show cable dsg counts "+DS+"/16"
    #    device.get_response(cmd)
     #   # parse the response
      #  matches = pattern.finditer(device.response)
       # for match in matches:
        #    sys.stdout.write('.')
         #   count.append({"tunnel": match.group("tunnel"), "count": int(match.group("packets"))})
#    for i in range(len(count)):
 #       for j in tunnels:
  #          if j['tunnel'] == count[i]['tunnel']:
   #             count[i]['type'] = j['type']
    #return count

def getDSGcounts(device, DS, tunnels):
    counts = []
    # get DSG counts
    if getattr(device, 'dsg_counts', None) is None:
        cmd = "show cable dsg counts"
        device.dsg_counts = device.get_response(cmd)
    # for each tunnel
    for tunnel in tunnels:
        sys.stdout.write('.')
        match = re.search(r"^"+DS+r"/\d{1,2}[ ]+"+tunnel['tunnel']+r"[ ]+\d+[ ]+(?P<packets>\d+)", device.dsg_counts, re.M)
        if match is not None:
            counts.append({'tunnel': tunnel['tunnel'], 'count': int(match.group('packets')), 'type': tunnel['type']})
    return counts

#def getSNR(device, mac, US):
 #   snr = []
  #  # get the response
   # cmd = f"show cable noise {mac}"
    #device.get_response(cmd)
    # parse the response
#    pattern = re_ext.compile(r"^(?P<channel>(\d{1,2}/){2}\d{1,2})[ ]+\d{1,3}[ ]+(?P<snr>[\d.]+)[ ]+")
 #   matches = pattern.finditer(device.response)
  #  for match in matches:
   #     channelSNR = float(match.group("snr"))
    #    if channelSNR != 0:
     #       snr.append({"channel": match.group("channel"), "snr": channelSNR})
#    return snr

def getSNR(device, mac, US):
    snr_readings = []
    # get noise readings
    if getattr(device, 'snr', None) is None:
        cmd = "show cable noise"
        device.snr = device.get_response(cmd)
    # determine the cable-mac
    cable_mac = r"\d+"
    match = re.search(r"\d+", mac)
    if match is not None:
        cable_mac = match.group(0)
    # get each channels SNR
    matches = re.finditer(r"^(?P<channel>"+US+r"/\d{1,2})[ ]+"+cable_mac+"+[ ]+(?P<snr>\d+(\.\d+)?)", device.snr, re.M)
    for match in matches:
        sys.stdout.write('.')
        # convert SNR to a float
        snr = float(match.group('snr'))
        # only keep non-zero SNR readings
        if snr != 0:
            snr_readings.append({'channel': match.group('channel'), 'snr': snr})
    return snr_readings

#def cmCount(device, mac):
 #   count = {'online': 0, 'total': 0}
  #  begin = mac[mac.rfind(" ")+1:len(mac):1]
   # # get the response
    #cmd = f"show cable modem {mac} count"
#    device.get_response(cmd)
 #   # parse the response
  #  lines = device.response.split('\n')
   # for i in lines[1:-1]:
    #    if "Found" in i:
     #       i = ps.minSpaces(i)
      #      count['online'] = int(ps.returnN(i,2))
       #     count['total'] = int(ps.returnN(i,1))
#    return count

def cmCount(device, mac):
    counts = {'online': 0, 'total': 0}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the cable-mac number
    number = None
    match = re.search(r"\d+", mac)
    if match is not None:
        number = match.group(0)
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^"+number+r"[ ]+(?P<total>\d+)[ ]+(?P<operational>\d+)[ ]+(?P<disabled>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
        if match is not None:
            counts['total'] = int(match.group('total'))
            counts['online'] = int(match.group('operational'))
    return counts

def cmCountTotal(session, expec):
    count = {'online': 0, 'total': 0}
    cmd = "show cable modem summary mac | include Total"
#  lines = p_ext.sendCMD(session, cmd, expec, 10)
  # found = False
    #for i in lines[1:-1]:
      # if "Total" in i:
        #  if found:
          #   i = ps.minSpaces(i)
            #  count['online'] = int(ps.returnN(i,2))
              # count['total'] = int(ps.returnN(i,1))
            #else:
              # found = True
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    pattern = r"^Total[ ]+(\d+)[ ]+(\d+)"
    match = re_ext.getMatch(output, pattern)
    if match != None:
        count['total'] = match.group(1)
        count['online'] = match.group(2)
    return count

# CMTS operations
def clearModems(session, expec):
    cmd = "clear cable modem offline delete"
    lines = p_ext.sendCMD(session, cmd, expec, 20)

###########################################
# network functions
###########################################
def getAllIPs(session, expec):
    ipv4 = []
    # get list of interfaces that are up/up
    up_interfaces = []
    cmd = "show ip interface brief | exclude Down|OOS|0.0.0.0"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[3:-1]:
        lineWords = ps.minSpaces(line).split(" ")
        interface = lineWords[0]+" "+lineWords[1]
        if interface not in up_interfaces:
            up_interfaces.append(interface)
    # get IPv4s from up/up interfaces
    cmd = "show running-config verbose | include ip\ address | exclude no\ ip\ address|prefix-list"
    lines = p_ext.sendCMD(session, cmd, expec, 20)
    for line in lines[1:-1]:
        lineWords = ps.minSpaces(line).split(" ")
        # get interface
        interface = lineWords[2]+" "+lineWords[3]
        # if this is an up/up interface
        if interface in up_interfaces:
            ip = lineWords[6]
            subnet = str(n.mask_prefix(lineWords[7]))
            network = n.nthIPv4(ip+"/"+subnet, 0)
            # add IPv4 data to address list
            ipv4.append({"Interface": interface, "Network": network, "Assigned": ip, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
    ipv6 = []
    cmd = "show ipv6 interface | include Admin\ State|Link-local|subnet\ is|cable-mac|loopback|ethernet"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-3:
        if "cable-mac" in lines[i] or "loopback" in lines[i] or "ethernet" in lines[i]:
            interface = lines[i][:lines[i].find(",")]
            if "Admin State / Oper State" in lines[i+1]:
                # get interface status
                state = lines[i+1][lines[i+1].find(":")+1:].replace(" ","")
                # if interface is up/up
                if state == "Up/IS" and "Link-local address" in lines[i+2]:
                    # get the link-local address
                    linkLocal = lines[i+2][lines[i+2].find(":")+1:].replace(" ","")
                    if "Global unicast" in lines[i+3]:
                        # get interface IPv6 address
                        while "subnet is" in lines[i+3]:
                            #print(lines[i+3])
                            addressWords = ps.minSpaces(lines[i+3].lower()).split(" ")
                            for j in range(len(addressWords)):
                                if addressWords[j] == "subnet":
                                    ip = addressWords[j-1].replace(",","").lower()
                                    network = addressWords[j+2].lower()
                                    # calculate first two hexadecimals
                                    [first, sec] = n.first2Hextets(network)
                                    # add IPv6 data to address list
                                    ipv6.append({"Interface": interface, "Network": network, "Assigned": ip, "First Hex": first, "Sec Hex": sec, "Link-Local": linkLocal.split("/")[0]})
                                    break
                            i += 1
        i += 1
    # get static routes
    cmd = "show running-config verbose | include configure\ ipv6\ route"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[1:-1]:
        lineWords = ps.minSpaces(line).split(" ")
        # get the network
        network = lineWords[3]
        # get the interface
        interface = lineWords[4]
        # if this is a null route, make the interface a prefix-delegation
        if interface == "null":
            interface = "PD"
        if network != "::/0":
            # calculate first two hexadecimals
            [first, sec] = n.first2Hextets(network)
            # add IPv6 data to address list
            ipv6.append({"Interface": interface, "Network": network, "Assigned": network.split("/")[0], "First Hex": first, "Sec Hex": sec, "Link-Local": ""})
    return [ipv4, ipv6]

def getRoute(session, expec, address):
    route = {"Network": "", "Process": "", "Next-Hop": "", "Interface": "", "Child-Hop": ""}
    # if this is an IPv6 network
    if ":" in address:
        cmd = "show ipv6 route "+address+" detail"
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if "IPv6 Route Dest" in line:
                route["Network"] = line[line.find(":")+1:].replace(" ","")
            elif "Next Hop" in line:
                route["Next-Hop"] = line[line.find(":")+1:].replace(" ","")
            elif "Protocol" in line:
                process = ps.minSpaces(line[line.find(":")+1:])
                route["Process"] = process.split(" ")[0]
                if route["Process"] == "local":
                    route["Next-Hop"] = "None"
            elif "Interface" in line:
                route["Interface"] = ps.minSpaces(line[line.find(":")+1:])
                break
    # if this is an IPv4 network
    else:
        cmd = "show ip route "+address+" detail"
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if "IPv4 Route Dest" in line:
                route["Network"] = line[line.find(":")+1:].replace(" ","")
            elif "Next Hop" in line:
                route["Next-Hop"] = line[line.find(":")+1:].replace(" ","")
            elif "Protocol" in line:
                process = ps.minSpaces(line[line.find(":")+1:])
                route["Process"] = process.split(" ")[0]
                if route["Process"] == "local":
                    route["Next-Hop"] = "None"
            elif "Interface" in line:
                route["Interface"] = ps.minSpaces(line[line.find(":")+1:])
                break
    return route

###############
##### NEW #####
###############
import re

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show image | include Version"
    device.get_response(cmd)
    # parse the response
    match = re.search(r"^Version:[ ]+(?P<version>\S+)", device.response, re.M)
    if match is not None:
        version = match.group('version').replace('CER_V','').strip()
    return version

def get_gen_type(device):
    # get the response
    cmd = "show linecard status"
    device.get_response(cmd)
    # parse the response
    if re.search(r"/RSM2", device.response) is not None:
        return 'Gen2'
    return 'Gen1'

############################################################
############### Networking #################################
############################################################
def get_ips(device, link_local=True):
    ipv4 = []
    ipv6 = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get IPv4 addresses
    matches = re.finditer(r"^configure interface (?P<interface>(cable-mac \d+\.\d+|ethernet \d+/\d+\.\d+|loopback \d+)) "+
                          r"ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    for match in matches:
        # get the IP address
        ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
        # if this is a valid IP address
        if ip.valid:
            # get the interface name
            interface = match.group('interface')
            # add IPv4 data to address list
            #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
            ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get IPv6 addresses
    matches = re.finditer(r"^configure interface (?P<interface>(cable-mac \d+\.\d+|ethernet \d+/\d+\.\d+|loopback \d+)) "+
                          r"ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", device.config, re.M)
    for match in matches:
        # get the IP address
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # get the interface name
            interface = match.group('interface')
            # calculate the first three half-hextets
            first_hex, sec_hex, third_hex = ip.first_three
            # add IPv6 data to address list
            #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
            ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    if link_local:
        # get IPv6 link-local addresses
        cmd = "show ipv6 interface | include VRF|^Link"
        device.get_response(cmd)
        matches = re.finditer(r"^(?P<interface>(cable-mac \d+\.\d+|ethernet \d+/\d+\.\d+|loopback \d+)),.+\n"+
                              r"Link-local address[ ]+:[ ]+(?P<ip>[\da-fA-F:]+/\d{1,3})", device.response, re.M)
        for match in matches:
            # get the link-local address
            ip = n.IP(match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # get the interface name
                interface = match.group('interface')
                # add the address to the previous entries
                for i in range(len(ipv6)):
                    if ipv6[i]['Interface'] == interface:
                        ipv6[i]['Link-Local'] = ip.addr
#                    if ipv6[i]['interface'] == interface:
 #                       ipv6[i]['link_local'] = ip.addr
    # get IPv6 aggregate routes
    interface = 'PD'
    matches = re.finditer(r"^configure ipv6 route (?P<ip>[\da-fA-F:]+/\d{1,3}) null", device.config, re.M)
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
#    cmd = "show ip interface"
 #   device.get_response(cmd)
  #  matches = re.finditer(r"^(?P<interface>(loopback|ethernet|cable-mac) \d+(/\d+)?(\.\d+)?), .*, IP Address: (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})\n"+
   #                       r"(.+\n)*?"+
    #                      r"Secondary IP Address\(es\):\n"+
     #                     r"(?P<secondaries>[ ]+((\d{1,3}\.){3}\d{1,3}|No Secondary Addresses).*)\n", device.response, re.M)
#    for match in matches:
 #       interface = match.group('interface')
  #      ip = n.IP(match.group('ip'))
   #     if ip.valid:
    #        # add IPv4 data to address list
     #       ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
      #  # get secondary IPs
       # pattern = re.compile(r"(?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})")
        #secondaries = pattern.finditer(match.group('secondaries'))
#        for secondary in secondaries:
 #           ip = n.IP(secondary.group('ip'))
  #          if ip.valid:
   #             # add IPv4 data to address list
    #            ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get IPv6 addresses
#    cmd = "show ipv6 interface"
 #   device.get_response(cmd)
    # search the output
  #  pattern = re.compile(r"^(?P<interface>[\S ]+), VRF:.*\n"+
   #                      r"Admin State .*\n"+
    #                     r"Link-local address[ ]+: (?P<link_local>[\da-fA-F:]+)/\d{1,3}\n"+
     #                    r"Global unicast address\(es\)[ ]+:"+
      #                   r"(?P<ips>([ ]+[\da-fA-F:]+.*\n)*)", re.M)
#    matches = pattern.finditer(device.response)
 #   # for each match
  #  for match in matches:
   #     interface = match.group('interface')
    #    link_local = n.IP(match.group('link_local'))
     #   if link_local.valid:
      #      # get all interface IPs
       #     pattern = re.compile(r"(?P<ip>[\da-fA-F:]+), subnet is [\da-fA-F:]+/(?P<prefix>\d{1,3})")
        #    all_ips = pattern.finditer(match.group('ips'))
         #   for each_ip in all_ips:
          #      ip = n.IP(each_ip.group('ip')+'/'+each_ip.group('prefix'))
           #     if ip.valid:
            #        first, sec = n.first2Hextets(ip.network)
             #       # add IPv6 data to address list
              #      ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec, 'Link-Local': link_local.addr})
    # get static routes
#    interface = 'PD'
 #   matches = re.finditer(r"^configure ipv6 route (?P<ip>[\da-fA-F:/]+) null", device.config, re.M)
  #  # for each match
   # for match in matches:
    #    ip = n.IP(match.group('ip'))
     #   if ip.valid:
      #      first, sec = n.first2Hextets(ip.network)
       #     # add IPv6 data to address list
        #    ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec, 'Link-Local': link_local.addr})
    return ipv4, ipv6

def get_route(device, address):
    route = {'Network': '', 'Process': '', 'Next-Hop': '', 'Interface': '', 'Child-Hop': ''}
    # if this is an IPv4 network
    if address.type == 4:
        cmd = "show ip route "+address.addr+" detail"
    # if this is an IPv6 network
    else:
        if address.addr == '::':
            cmd = "show ipv6 route ::/0 detail"
        else:
            cmd = "show ipv6 route "+address.addr+" detail"
    # get the route
    device.get_response(cmd)
    match = re.search(r"[ ]+IPv(4|6) Route Dest:[ ]+(?P<network>\S+)\n"+
                      r"[ ]+Next Hop:[ ]+(?P<next_hop>\S+)\n"+
                      r"([ ]+.+\n)+"+
                      r"[ ]+Protocol:[ ]+(?P<process>\S+)( .*)?\n"+
                      r"([ ]+.+\n)+"+
                      r"[ ]+Interface:[ ]+(?P<interface>[\S ]+)", device.response)
    if match is not None:
        route['Network'] = match.group('network')
        route['Next-Hop'] = match.group('next_hop')
        route['Process'] = match.group('process')
        if route['Process'] == 'local':
            route['Next-Hop'] = address.addr
        route['Interface'] = match.group('interface')
    return route

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
    match = re.search(r"^Total[ ]+(?P<total>\d+)[ ]+(?P<operational>\d+)", device.response, re.M)
    if match is not None:
        count['online'] = match.group('operational')
        count['total'] = match.group('total')
    return count

## MAC Domain
def get_mac_domains(device):
    macs = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all mac-domains
    matches = re.finditer(r"^configure interface (?P<mac>cable-mac \d+)", device.config, re.M)
    for match in matches:
        mac = match.group('mac')
        if mac not in macs:
            macs.append(mac)
    # sort the MACs
    macs = sorted(macs)
    macs = sorted(macs, key=len)
    return macs

def get_mac_description(device, mac):
    description = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    match = re.search(r"^configure interface "+mac+r" description \"(?P<description>[\S ]+)\"", device.config, re.M)
    if match is not None:
        description = match.group('description')
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get DS
    match = re.search(r"^configure interface cable-downstream (?P<ds>\d{1,2}/\d{1,2})/\d{1,2} cable "+mac+r"\b", device.config, re.M)
    if match is not None:
        DS = match.group('ds')
    # get US
    match = re.search(r"^configure interface cable-upstream (?P<us>\d{1,2}/\d{1,2})/\d{1,2} cable "+mac+r"\b", device.config, re.M)
    if match is not None:
        US = match.group('us')
    return DS, US

def get_mac_connector(device, US):
    connector = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get connector from the US
    match = re.search(r"^configure interface cable-upstream "+US+"/\d+ cable connector (?P<connector>\d+)", device.config, re.M)
    if match is not None:
        connector = match.group('connector')
    return connector

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # count DS
    matches = re.finditer(r"^configure interface cable-downstream (\d{1,2}/){2}\d{1,2} cable "+mac+r"\b", device.config, re.M)
    for match in matches:
        counts['DS'] += 1
    # count OFDM
    matches = re.finditer(r"^configure interface cable-downstream (\d{1,2}/){2}\d{1,2} ofdm "+mac+r"\b", device.config, re.M)
    for match in matches:
        counts['OFDM'] += 1
    # count US
    matches = re.finditer(r"^configure interface cable-upstream (\d{1,2}/){2}\d{1,2} cable "+mac+r"\b", device.config, re.M)
    for match in matches:
        counts['US'] += 1
    return counts

def get_mac_cm_counts(device, mac):
    counts = {'online': 0, 'total': 0, 'percent': 100}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the cable-mac number
    number = None
    match = re.search(r"\d+", mac)
    if match is not None:
        number = match.group(0)
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^"+number+r"[ ]+(?P<total>\d+)[ ]+(?P<operational>\d+)[ ]+(?P<disabled>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
        if match is not None:
            counts['total'] = int(match.group('total'))
            counts['online'] = int(match.group('operational'))
            if counts['total'] > 0:
                counts['percent'] = round((counts['online']/counts['total'])*100, 1)
    return counts

def get_mac_IP_interface(device, mac):
    interface = mac
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # check if this is a slave bundle
    match = re.search(r"^configure interface "+mac+r" cable bundle (?P<interface>cable-mac \d+)", device.config, re.M)
    if match is not None:
        interface = match.group('interface')
    return interface

def get_mac_IPs(device, mac):
    ipv4 = []
    ipv6 = []
    ipv4helper = []
    ipv6helper = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get IPv4 addresses
    matches = re.finditer(r"^configure interface (?P<interface>"+mac+r"\.\d+) ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
        if ip.valid:
            ipv4.append({'interface': match.group('interface'), 'address': str(ip)})
    # get IPv4 helpers
    matches = re.finditer(r"^configure interface "+mac+r"\.\d+ cable helper-address (?P<ip>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid and ip.addr not in ipv4helper:
            ipv4helper.append(ip.addr)
    # get IPv6 addresses
    matches = re.finditer(r"^configure interface (?P<interface>"+mac+r"\.\d+) ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid:
            ipv6.append({'interface': match.group('interface'), 'address': str(ip)})
    # get IPv6 helpers
    matches = re.finditer(r"^configure interface "+mac+r"\.\d+ ipv6 dhcp relay destination (?P<ip>[\da-fA-F:]+)", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid and ip.addr not in ipv6helper:
            ipv6helper.append(ip.addr)
    return ipv4, ipv4helper, ipv6, ipv6helper

def get_mac_DSG_tunnels(device, DS):
    tunnels = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all tunnel groups
    tgs = []
    matches = re.finditer(r"^configure interface cable-downstream "+DS+r"/\d{1,2} cable dsg tunnel-group (?P<tg>\d+)", device.config, re.M)
    for match in matches:
        tg = match.group('tg')
        if tg not in tgs:
            tgs.append(tg)
    # get all tunnels in tunnel groups
    for tg in tgs:
        matches = re.finditer(r"^configure cable dsg tunnel (?P<tunnel>\d+) tunnel-group "+tg+r" client-id-list (?P<client_list>\d+) mac-address (?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})", device.config, re.M)
        for match in matches:
            tunnels.append({'index': match.group('tunnel'), 'group': tg, 'client-list': {'id': match.group('client_list'), 'data':[]}, 'mac': match.group('mac')})
    # for each tunnel found
    for i in range(len(tunnels)):
        # collect additional tunnel information
        match = re.search(r"^configure cable dsg tunnel "+tunnels[i]['index']+r" classifier (?P<classifier>\d+) priority \d+ source-network (?P<src>(\d{1,3}\.){3}\d{1,3}) dest-ip (?P<dest>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
        if match is not None:
            tunnels[i]['classifier'] = match.group('classifier')
            tunnels[i]['source'] = match.group('src')
            tunnels[i]['multicast'] = match.group('dest')
        # collect client-list data
        matches = re.finditer(r"^configure cable dsg client-id-list "+tunnels[i]['client-list']['id']+r" index (?P<index>\d+) type (?P<type>\S+) value (?P<value>\S+)", device.config, re.M)
        for match in matches:
            tunnels[i]['client-list']['data'].append({'index': match.group('index'), 'type': match.group('type'), 'value': match.group('value')})
    # determine tunnel type
    for i in range(len(tunnels)):
        tunnels[i]['type'] = get_tunnel_type(tunnels[i])
    return tunnels

def get_tunnel_type(tunnel):
    tunnel_type = 'Unknown'
    # if a client-list was found
    if tunnel.get('client-list') is not None and len(tunnel['client-list']['data']) > 0:
        client_list = tunnel['client-list']['data']
        # if client-list only has one index
        if len(client_list) == 1:
            if client_list[0]['type'] == 'broadcast':
                if client_list[0]['value'] == '1':
                    tunnel_type = 'Cisco Global'
                elif client_list[0]['value'] == '2':
                    tunnel_type = 'EAS'
                elif client_list[0]['value'] == '5':
                    tunnel_type = 'DCAS CVT'
                elif client_list[0]['value'] == '55555':
                    tunnel_type = 'DCAS SI'
                elif client_list[0]['value'] == '55556':
                    tunnel_type = 'DCAS CVT 2'
            elif client_list[0]['type'] == 'ca-system-id':
                if client_list[0]['value'] == '0x700':
                    tunnel_type = 'ARRIS CA'
                elif client_list[0]['value'] == '0x701':
                    tunnel_type = 'ARRIS DSP'
                elif client_list[0]['value'] == '0x96b':
                    tunnel_type = 'DCAS CA'
                elif client_list[0]['value'] == '0xe00':
                    tunnel_type = 'Cisco Hub'
            elif client_list[0]['type'] == 'application-id':
                if client_list[0]['value'] == '1':
                    tunnel_type = 'ARRIS EPG'
                elif client_list[0]['value'] == '2':
                    tunnel_type = 'ODN TSB'
                elif client_list[0]['value'] == '5':
                    tunnel_type = 'ADB XAIT'
                elif client_list[0]['value'] == '6':
                    tunnel_type = 'ARRIS SDV'
                elif client_list[0]['value'] == '2000':
                    tunnel_type = 'DCAS EPG'
        elif len(client_list) == 2:
            # if 'ca-system-id' is not first
            if client_list[0]['type'] != 'ca-system-id':
                # flip the list
                client_list = [client_list[1], client_list[0]]
            if client_list[0]['type'] == 'ca-system-id' and client_list[1]['type'] == 'mac-address':
                if client_list[0]['value'] == '0xe00':
                    if client_list[1]['value'].startswith('0001.a6fe.'):
                        tunnel_type = 'Cisco System'
                    elif client_list[1]['value'].startswith('0001.a6ff.'):
                        tunnel_type = 'Cisco Hub or CMTS Bridge'
    return tunnel_type    

def get_mac_video_interface(device, DS):
    interface = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get video interface
    match = re.search(r"^configure interface cable-downstream "+DS+r"/\d{1,2} video (?P<interface>virtual-edge \d+)", device.config, re.M)
    if match is not None:
        interface = match.group('interface')
    return interface

def get_mac_video(device, DS):
    video = {}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get the number of channels
    video['num_channels'] = 0
    matches = re.finditer(r"^configure interface cable-downstream "+DS+r"/\d{1,2} video virtual-edge \d+ tsid \d+", device.config, re.M)
    for match in matches:
        video['num_channels'] += 1
    # get port and starting channel
    match = re.search(r"^configure interface cable-downstream "+DS+r"/(?P<rf_chan_start>\d{1,2}) video "+
                      r"virtual-port (?P<port>\d+) virtual-channel (?P<start_chan>\d+)", device.config, re.M)
    if match is None:
        return {}
    start_rf_chan = match.group('rf_chan_start')
    video['start_channel'] = int(match.group('start_chan'))
    video['qam_port'] = int(match.group('port'))
    # get virtual-edge and starting TSID
    match = re.search(r"^configure interface cable-downstream "+DS+r"/"+start_rf_chan+r" video "+
                      r"virtual-edge (?P<ve>\d+) tsid (?P<tsid_start>\d+)", device.config, re.M)
    if match is None:
        return {}
    video['start_tsid'] = int(match.group('tsid_start'))
    video['virtual-edge'] = match.group('ve')
    # get virtual-edge MGMT loopback
    match = re.search(r"^configure video virtual-edge "+video['virtual-edge']+r" erm-session source-interface loopback (?P<loopback>\d+)", device.config, re.M)
    if match is None:
        return {}
    # get virtual-edge MGMT IP
    match = re.search(r"^configure interface loopback "+match.group('loopback')+r" ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    if match is None:
        return {}
    video['mgmt_ip'] = match.group('ip')
    # get virtual-edge ingest loopback
    match = re.search(r"^configure video virtual-edge "+video['virtual-edge']+r" data-interface loopback (?P<loopback>\d+) input-port (?P<ingest_port>\d+)", device.config, re.M)
    if match is None:
        return {}
    video['ingest_port'] = match.group('ingest_port')
    # get virtual-edge ingest IP
    match = re.search(r"^configure interface loopback "+match.group('loopback')+r" ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    if match is None:
        return {}
    video['ingest_ip'] = match.group('ip')
    # get starting frequency
    match = re.search(r"^configure interface cable-downstream "+DS+r"/"+start_rf_chan+r" video frequency (?P<start_freq>\d{3})\d+", device.config, re.M)
    if match is None:
        return {}
    video['start_freq'] = int(match.group('start_freq'))
    # get SG number
    match = re.search(r"^configure interface cable-downstream "+DS+r"/"+start_rf_chan+r" video service-group \"[\S ]+\" service-group-index (?P<num>\d+)", device.config, re.M)
    if match is None:
        return {}
    video['sg_num'] = match.group('num')
    return video

############################################################
############### CM #########################################
############################################################
def get_modem(device, modem, query_value, query_type):
    # declare command set
    cmd_sets = {
               'MAC':  [
                        f"show cable modem {query_value}",
                        f"show cable modem cpe-mac {query_value}"
                       ],
               'IPv4': [
                        f"show cable modem {query_value}",
                        f"show cable modem cpe-ip {query_value}"
                       ],
               'IPv6': [
                        f"show cable modem cm-ipv6 {query_value}",
                        f"show cable modem cpe-ipv6 {query_value}"
                       ]
              }
    # get commands to run
    cmds = None
    for key, cmd_set in cmd_sets.items():
        if key.lower() in query_type.lower():
            cmds = cmd_set
    # declare set of valid CM states
    states = [
              'operational', 'rang', 'online-d', 'denied',
              'dhcpv', 'register', 'tftp', 'eaestart',
              'frwddisable', 'regbpiinit', 'rfmuteall', 'rngaborted',
              'offline'
             ]
    states_string = r"("
    for state in states:
        states_string += state+r"|"
    states_string = states_string[:-1]+r")"
    # for each command
    modem.output = ''
    for cmd in cmds:
        # send the command
        device.get_response(cmd)
        modem.output += '\n'+device.response
        # search the output for the MAC
        match = re.search(r"^\d{1,2}/\d{1,2}/\d{1,2}-\d{1,2}/\d{1,2}/\d{1,2}[ ]+\d+[ ]+((\S+|-)[ ]+)?(?P<state>\S*"+states_string+r"\S*)[ ]+"+
                          r"\d\.\d[ ]+((\S+/\S+|-)[ ]+)?\d+[ ]+(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<ip>[\da-fA-F:.]+)?", device.response, re.M|re.I)
        if match is not None:
            modem.mac = match.group('mac')
            modem.state = match.group('state')
            if 'offline' not in modem.state.lower():
                modem.offline = False
            else:
                modem.offline = True
            ip = match.group('ip')
            if ip is not None:
                if ':' not in ip:
                    modem.ipv4 = ip
                else:
                    modem.ipv6 = ip
            modem.output = device.response
            break
#    if match is None:
 #       modem.output = modem.output[1:]
    return modem

