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
    cmd_set = {"MAC":  ["show cable modem "+queryValue+" | begin ^MAC\ Address"
                                            #"show cable modem "+queryValue
                                          ],
                          "IPv4": ["show cable modem "+queryValue+" | begin ^MAC\ Address"
                                            #"show cable modem "+queryValue
                                          ],
                          "IPv6": ["show cable modem "+queryValue+" | begin ^MAC\ Address"
                                            #"show cable modem "+queryValue
                                          ]
                        }
    # declare set of valid CM states
    states = ["online", "init", "reject", "expire", "resetting"]

    # send commands
    for cmd in cmd_set[queryType]:
        output = []
        # execute the command
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # for each line in the output
        for line in lines[1:-1]:
            # keep the output for later use
            if "Offset" not in line:
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
        if col.get("MAC Address") != None:
            # for each row in the table
            for row in table[1:]:
                # get the value in the MAC address column
                mac = row[col["MAC Address"]]
                # if this was a valid MAC address
                if n.validMAC(mac):
                    # store the MAC as the CM MAC
                    cm_mac = mac
                    break
    return [online, cm_mac]

def getCM_phy(session, expec, cm_mac):
    phy = {"US SNR": "", "DS SNR": "", "US Power TX": "", "US Power RX": "0", "DS Power": ""}
    associations = {"US SNR": "USMER", "DS SNR": "DSMER", "US Power TX": "USPwr", "DS Power": "DSPwr"}
    # send command
    cmd = "show cable modem "+cm_mac+" phy | begin ^MAC Address"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # only keep the output needed
    output = []
    for line in lines[1:-1]:
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
    cmd = "show cable modem "+cm_mac+" | begin ^MAC\ Address"
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
            if n.validIPv4(ip):
                # store the MAC as the CM MAC
                cm_ip = ip
                break
            # if the CM has an IPv6 address
            elif ip == "---":
                cm_ip = ip
    # if the CM has an IPv6 address
    if cm_ip == "---":
        cm_ip = ""
        # send command
        cmd = "show cable modem "+cm_mac+" ipv6 | begin ^MAC\ Address"
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # only keep the output needed
        output = []
        for line in lines[1:-1]:
            if len(line) < 3:
                break
            output.append(line)
        # look for an IPv6 address in the output
        for line in output:
            # look at each word in the output
            words = ps.minSpaces(line).split(" ")
            for word in words:
                # if the word is possibly an IPv6 address
                if ":" in word:
                    # if the word is a valid IPv6 address
                    if n.validIPv6(word):
                        # store the IP as the CM IP
                        cm_ip = word.lower()
                        break
    return cm_ip

def getCM_macDomain(session, expec, cm_mac):
    cm_domain = ""
    # send command
    cmd = "show cable modem "+cm_mac+" | begin ^MAC\ Address"
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
    if col.get("I/F") != None:
        # get the value in the MAC domain column
        cm_domain = table[1][col["I/F"]]
        cm_domain = "Cable"+cm_domain[1:cm_domain.rfind("/")]
    return cm_domain

def testPing(session, expec, ip, count, fail_threshold):
    success = True
    # initialize counts
    passed = 0
    failed = 0
    # create ping command
    if ":" in ip:
        cmd = "ping ipv6 "+ip+" repeat 1 timeout 1"
    else:
        cmd = "ping ip "+ip+" repeat 1 timeout 1"
    # for the number of pings
    for i in range(count):
        # send one ping
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # look at each line in the output
        for line in lines[1:-1]:
            # if this line contains the pings sent and recieved
            if "Success rate" in line:
                # parse out only the received
                piece = line[line.find("(")+1:line.find(")")].split("/")
                if len(piece) > 1:
                    result = piece[1]
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
    cmd = "terminal width 0"
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
    cmd = "show version | include Software"
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    pattern = re_ext.compile(r"Version[ ]+(\S+)")
    match = pattern.search(output)
    if match:
        version = match.group(1)
    return version

# cmts-status info gathering
#def ipConnectivity(device, ips, iphelper):
 #   results = []
  #  for ip in ips:
   #     sys.stdout.write(".")
    #    # get the response
     #   cmd = f"ping {iphelper} source {ip['address'].split('/')[0]}"
      #  device.get_response(cmd)
       # # parse the response
        #lines = device.response.split('\n')
#        for i in lines[1:]:
 #           if "Success rate" in i:
  #              i = ps.minSpaces(i)
   #             result = ps.returnN(i,5)
    #            result = result.replace(',','').replace('(','').replace(')','')
     #           result = result.replace('(','')
      #          [recieved, transmitted] = result.split('/')
       #         results.append({'ip': ip['address'], 'recieved': recieved, 'transmitted': transmitted})
        #        break
#    return results

def ipConnectivity(device, ips, iphelper):
    pings = []
    # for each IP
    for ip in ips:
        sys.stdout.write('.')
        # send pings
        cmd = f"ping {iphelper} source {ip['address'].split('/')[0]}"
        device.get_response(cmd)
        # get the pings counts
        match = re.search(r"^Success rate is \S+ percent \((?P<received>\d+)/(?P<sent>\d+)\),", device.response, re.M)
        if match is not None:
            pings.append({'ip': ip['address'], 'recieved': match.group('received'), 'transmitted': match.group('sent')})
    return pings

#def channelStatus(device, mac, DS, US):
 #   dsStatus = []
  #  usStatus = []
   # channels = ""
    # get the response
#    cmd = f"show running-config interface {mac}"
 #   device.get_response(cmd)
  #  # parse the response
   # lines = device.response.split('\n')
    #for i in lines[1:]:
     #   if "rf-chan" in i:
      #      i = ps.minSpaces(i)
       #     channels += " "+ps.returnN(i,4)
    # get the response
#    cmd = f"show controllers Integrated-Cable {DS} rf-channel{channels}"
 #   device.get_response(cmd)
  #  # parse the response
   # lines = device.response.split('\n')
    #for i in lines[1:]:
     #   i = ps.minSpaces(i)
      #  if " 256 " in i or "OFDM" in i:
       #     if "OFDM" in i:
        #        frequency = ps.returnN(i,4)[0:3]+" MHz"
         #       try:
          #          power = ps.returnN(i,9)
           #     except:
            #        power = "-"
#            else:
 #               frequency = ps.returnN(i,3)[0:3]+" MHz"
  #              try:
   #                 power = ps.returnN(i,10)
    #            except:
     #               power = "-"
      #      sys.stdout.write(".")
       #     dsStatus.append({'channel': DS+":"+ps.returnN(i,0), 'status': ps.returnN(i,1), 'frequency': frequency, 'power': power+" dBmV"})
    # get the response
#    cmd = f"show controllers Upstream-Cable {US} | include OpState|Frequency"
 #   device.get_response(cmd)
  #  # parse the response
   # lines = device.response.split('\n')
    #for i in lines[1:]:
     #   i = ps.minSpaces(i)
      #  if "AdminState:UP" in i:
       #     sys.stdout.write(".")
        #    channelData = {'channel': US+":"+ps.returnN(i,3), 'status': ps.returnN(i,6), 'power': '-'}
#        elif "Frequency" in i:
 #           try:
  #              frequency = float(ps.returnN(i,1))
   #             width = float(ps.returnN(i,5))
    #            startFreq = str(round(frequency - width/2,3))
     #           endFreq = str(round(frequency + width/2,3))
      #          channelData['frequency'] = startFreq+"-"+endFreq+" MHz"
       #         usStatus.append(channelData)
        #    except:
         #       pass
#    return [dsStatus, usStatus]

def channelStatus(device, mac, DS, US):
    ds_status = []
    us_status = []
    # get the DS interface output
    cmd = f"show controllers Integrated-Cable {DS} rf-channel 0-162"
    device.get_response(cmd)
    # get the DOCSIS channels
    matches = re.finditer(r"^[ ]+(?P<channel>\d+)[ ]+(?P<status>\S+)[ ]+\S+[ ]+(?P<freq>\d{3})0{6}[ ]+DOCSIS[ ]+\S+[ ]+\d+[ ]+\S+[ ]+\S+[ ]+\d+[ ]+(?P<power>\d+\.\d+)", device.response, re.M)
    for match in matches:
        sys.stdout.write('.')
        ds_status.append({'channel': f"{DS}:{match.group('channel')}", 'status': match.group('status'), 'frequency': match.group('freq'), 'power': match.group('power')})
    # get the OFDM channels
    matches = re.finditer(r"^[ ]+(?P<channel>\d+)[ ]+(?P<status>\S+)[ ]+\S+[ ]+OFDM[ ]+\d+[ ]+\d+[ ]+(?P<plc>\d{3})0{6}[ ]+\d+[ ]+\d+[ ]+(?P<power>\d+\.\d+)", device.response, re.M)
    for match in matches:
        sys.stdout.write('.')
        ds_status.append({'channel': f"{DS}:{match.group('channel')}", 'status': match.group('status'), 'frequency': match.group('plc'), 'power': match.group('power')})
    # get the US interface output
    cmd = f"show controllers Upstream-Cable {US} | include OpState|Frequency"
    device.get_response(cmd)
    # get the US channels
    matches = re.finditer(r"^Controller "+US+r" upstream (?P<channel>\d+)[ ]+AdminState:\S+ OpState: (?P<status>\S+)\n+"
                          r"[ ]+Frequency (?P<freq>\d+\.\d)\d+ MHz, Channel Width (?P<width>\d+\.\d+) MHz", device.response, re.M)
    for match in matches:
        sys.stdout.write('.')
        center_freq = float(match.group('freq'))
        width = float(match.group('width'))/10
        bottom = round(center_freq-width/2,1)
        top = round(center_freq+width/2,1)
        us_status.append({'channel': f"{US}:{match.group('channel')}", 'status': match.group('status'), 'frequency': f"{bottom}-{top}", 'power': '-'})
    return ds_status, us_status

#def getMCounts(device, multicasts):
 #   counts = []
  #  for i in multicasts:
   #     # get the response
    #    cmd = f"show ip mroute {i['multicast']} {i['source']} count | include Packets"
     #   device.get_response(cmd)
      #  # parse the response
       # lines = device.response.split('\n')
        #for j in lines[1:]:
         #   if "Packets" in j:
          #      sys.stdout.write(".")
           #     j = ps.minSpaces(j)
            #    counts.append({'multicast': {'multicast': i['multicast'], 'source': i['source']}, 'count': int(ps.returnN(j,7)[:-1]), 'type': i['type'], 'tunnel': i['tunnel']})
#    return counts

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
        match = re.search(r"^Group: "+group+r",.* Packets forwarded: (?P<packets>\d+),.*\n"+
                          r"[ ]+Source: "+src+"/\d{1,2},", device.mcounts, re.M)
        if match is not None:
            counts.append({'multicast': {'multicast': mcast['multicast'], 'source': mcast['source']}, 'count': int(match.group('packets')),
                           'type': mcast['type'], 'tunnel': mcast['tunnel']})
    return counts

#def getDSGcounts(device, DS, tunnelData):
 #   count = []
  #  tunnels = []
   # # get the response
    #cmd = f"show interfaces Cable{DS} dsg downstream tg"
#    device.get_response(cmd)
 #   # parse the response
  #  lines = device.response.split('\n')
   # for i in lines[1:]:
    #    if "0100.5e" in i:
     #       i = ps.minSpaces(i)
      #      tunnels.append(ps.returnN(i,2))
#    for i in tunnels:
 #       # get the response
  #      cmd = f"show cable dsg tunnel {i} statistics"
   #     device.get_response(cmd)
    #    # parse the response
     #   lines = device.response.split('\n')
      #  for j in lines[1:]:
       #     j = ps.minSpaces(j)
        #    if ps.returnN(j,0)==i:
         #       sys.stdout.write('.')
          #      count.append({'tunnel': i, 'count': int(ps.returnN(j,5))})
#    for i in range(len(count)):
 #       for j in tunnelData:
  #          if j['tunnel'] == count[i]['tunnel']:
   #             count[i]['type'] = j['type']
    #return count

def getDSGcounts(device, DS, tunnels):
    counts = []
    # get DSG counts
    if getattr(device, 'dsg_counts', None) is None:
        cmd = "show cable dsg cfr verbose"
        device.dsg_counts = device.get_response(cmd)
    # for each tunnel
    for tunnel in tunnels:
        sys.stdout.write('.')
        match = re.search(r"^Tunnel Id[ ]+:[ ]+"+tunnel['tunnel']+r"\n"+
                          r"(\S+[ ]+.*\n)+"+
                          r"Forwarded[ ]+:[ ]+(?P<packets>\d+)", device.dsg_counts, re.M)
        if match is not None:
            counts.append({'tunnel': tunnel['tunnel'], 'count': int(match.group('packets')), 'type': tunnel['type']})
    return counts

#def getSNR(device, US):
 #   snr = []
  #  # get the response
   # cmd = f"show controllers Upstream-Cable {US} | include MER|UP"
    #device.get_response(cmd)
    # parse the response
#    lines = device.response.split('\n')
 #   for i in range(1, len(lines)-1):
  #      if "AdminState:UP" in lines[i]:
   #         sys.stdout.write('.')
    #        lines[i] = ps.minSpaces(lines[i])
     #       lines[i+1] = ps.minSpaces(lines[i+1])
      #      result = {'channel': ps.returnN(lines[i],1)+":"+ps.returnN(lines[i],3)}
       #     if "Unknown" in lines[i+1]:
        #        result['snr'] = float(0.0)
         #   else:
          #      result['snr'] = round(float(ps.returnN(lines[i+1],7)),1)
           # if result['snr'] != 0:
            #    snr.append(result)
#    return snr

def getSNR(device, US):
    snr_readings = []
    # get noise reading
    cmd = f"show controllers Upstream-Cable {US} | include MER|UP"
    device.get_response(cmd)
    # get each channels SNR
    matches = re.finditer(r"^Controller "+US+r" upstream (?P<channel>\d+)[ ]+AdminState:\S+[ ]+OpState: \S+\n"+
                          r"[ ]+US phy MER.* (?P<snr>\d+\.\d)\d+ dB", device.response, re.M)
    for match in matches:
        sys.stdout.write('.')
        # convert SNR to a float
        snr = float(match.group('snr'))
        # only keep non-zero SNR readings
        if snr != 0:
            snr_readings.append({'channel': f"{US}:{match.group('channel')}", 'snr': snr})
    return snr_readings

#def cmCount(device, mac):
 #   count = {'online': 0, 'total': 0}
  #  begin = f"C{mac[len('Cable'):len(mac):1]}/U"
   # # get the response
    #cmd = f"show cable modem {mac} summary"
#    device.get_response(cmd)
 #   # parse the response
  #  lines = device.response.split('\n')
   # for i in lines[1:]:
    #    if begin in i:
     #       i = ps.minSpaces(i)
      #      count['online'] += int(ps.returnN(i,3))
       #     count['total'] += int(ps.returnN(i,1))
#    return count

def cmCount(device, DS):
    counts = {'online': 0, 'total': 0}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the cable-mac number
    number = None
    match = re.search(r"\d+/\d+/\d+", DS)
    if match is not None:
        number = f"C{match.group(0)}"
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        matches = re.finditer(r"^"+number+r"/\w{2}[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<operational>\d+)[ ]+(?P<unregistered>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
        for match in matches:
            counts['total'] += int(match.group('total'))
            counts['online'] += int(match.group('operational'))
    return counts

def cmCountTotal(session, expec):
    count = {'online': 0, 'total': 0}
    cmd = "show cable modem summary total | include Total"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    found = False
    for i in lines[1:-1]:
        if "Total" in i:
            if found:
                i = ps.minSpaces(i)
                count['online'] = int(ps.returnN(i,3))
                count['total'] = int(ps.returnN(i,1))
            else:
                found = True
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
    bundles = []
    cmd = "show interfaces | include is\ up,\ line\ protocol|Internet\ address"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-2:
        if "line protocol" in lines[i] and "Video" not in lines[i]:
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
                # save Bundle interfaces for later use
                if "Bundle" in interface:
                    bundles.append(interface)
                i += 1
        i += 1
    # get secondary IPs from Bundle interfaces
    for bundle in bundles:
        cmd = "show running-config interface %s | include ^\ ip\ address" % bundle
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        for line in lines[1:-1]:
            if "secondary" in line:
                line = ps.minSpaces(line)
                subnet = str(n.mask_prefix(ps.returnN(line, 3)))
                ip = ps.returnN(line, 2)
                network = n.nthIPv4(ip+"/"+subnet, 0)
                ipv4.append({"Interface": bundle, "Network": network, "Assigned": ip, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
    # get CCAP video ingest IPs
    cmd = "show running-config | include ^\ \ logical-edge-device|^\ \ \ \ \ \ virtual-edge-input-ip"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-2:
        lineWords = ps.minSpaces(lines[i]).split(" ")
        if lineWords[0] == "logical-edge-device":
            addressWords = ps.minSpaces(lines[i+1]).split(" ")
            if addressWords[0] == "virtual-edge-input-ip":
                interface = "LED" + lineWords[len(lineWords)-1]
                ip = addressWords[1]
                network = n.nthIPv4(ip+"/32", 0)
                ipv4.append({"Interface": interface, "Network": network, "Assigned": ip, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
                i +=1
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
    # get static routes
    cmd = "show running-config | include ^ipv6\ route"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[1:-1]:
        lineWords = ps.minSpaces(line).split(" ")
        # get the network
        network = lineWords[2].lower()
        # get the interface
        interface = lineWords[3]
        # if this is a null route, make the interface a prefix-delegation
        if "Null" in interface:
            interface = "PD"
        # calculate first two hexadecimals
        [first, sec] = n.first2Hextets(network)
        # add IPv6 data to address list
        ipv6.append({"Interface": interface, "Network": network, "Assigned": network.split("/")[0], "First Hex": first, "Sec Hex": sec, "Link-Local": ""})
    return [ipv4, ipv6]

def getRoute(session, expec, address):
    ### same function as Cisco 9500, Cisco 4500, and Cisco CBR8 ###
    route = {"Network": "", "Process": "", "Next-Hop": "", "Interface": "", "Child-Hop": ""}
    # if this is an IPv6 network
    if ":" in address:
        if address == "::":
            address = "::/0"
        cmd = "show ipv6 route "+address
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # loop over the output
        routeBlock = False
        for line in lines[1:-1]:
            line = ps.minSpaces(line)
            if routeBlock:
                route["Next-Hop"] = line.split(" ")[0].lower().replace(",","")
                # if this is a ultimate route (has a exit interface)
                if "," in line or "via" in line:
                    # if this is a local route (IP is configured on this device)
                    if route["Process"] == "local":
                        route["Next-Hop"] = "None"
                    # if the IP is routed by this device
                    elif route["Process"] == "connected":
                        route["Next-Hop"] = address
                    # get the exit interface
                    routeWords = line.split(" ")
                    route["Interface"] = routeWords[len(routeWords)-1].lower()
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
                    network = ps.returnN(line, 3).lower()
                    route["Network"] = network
                elif "Known via" in line:
                    # determine the process the route was learned through
                    line = line[line.find("\"")+1:]
                    process = line[:line.find("\"")]
                    route["Process"] = process
                elif "Routing paths" in line:
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
                    route["Next-Hop"] = ps.returnN(line, 1).replace(",","").replace("directly","None")
                    # if this is a ultimate route (has a exit interface)
                    if "via" in line:
                        port = ps.returnN(line, len(line.split(" "))-1)
                        route["Interface"] = port
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
import cisco_9500 as c9500

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show version | include Software"
    device.get_response(cmd)
    # parse the response
    match = re.search(r"^Cisco.* Software, Version (?P<version>\S+)", device.response, re.M)
    if match is not None:
        version = match.group('version').strip()
    return version

############################################################
############### Networking #################################
############################################################
def get_ips(device):
    ipv4 = []
    # same as Cisco 9500
    first_ipv4, ipv6 = c9500.get_ips(device)
    # remove video interfaces
    for ip in first_ipv4:
        if 'video' not in ip['Interface'].lower():
            ipv4.append(ip)
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get Bundle interfaces
    bundle_matches = re.finditer(r"interface (?P<interface>Bundle\d+(\.\d+)?)\n"+
                                 r"( .+\n)+", device.config, re.M)
    pattern_v4 = re.compile(r"ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3})")
    pattern_v6 = re.compile(r"ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,2})")
    for bundle_match in bundle_matches:
        interface = bundle_match.group('interface')
        # get Bundle IPv4 addresses
        matches = pattern_v4.finditer(bundle_match.group(0))
        for match in matches:
             ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
             if ip.valid:
                # add IPv4 data to address list
                ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
        # get Bundle IPv6 addresses
        matches = pattern_v6.finditer(bundle_match.group(0))
        for match in matches:
             ip = n.IP(match.group('ip'))
             if ip.valid:
                first, sec = n.first2Hextets(ip.network)
                # add IPv6 data to address list
                ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec})
    # get video interfaces
    matches = re.finditer(r"^(?P<spaces>[ ]+)logical-edge-device \S+ id (?P<led>\d+)\n"+
                          r"(?P=spaces)[ ]+protocol .*\n"+
                          r"(?P=spaces)[ ]+mgmt-ip (?P<mgmt_ip>(\d{1,3}\.){3}\d{1,3})\n"+
                          r"((?P=spaces)[ ]+.*\n)*"+
                          r"(?P=spaces)[ ]+virtual-edge-input-ip (?P<ip>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    # for each match
    for match in matches:
        interface = f"LED{match.group('led')}"
        ip = n.IP(match.group('ip'))
        if ip.valid:
            # add IPv4 data to address list
            ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get static routes
    interface = 'PD'
    matches = re.finditer(r"^ipv6 route (?P<ip>[\da-fA-F:/]+) Null", device.config, re.M)
    # for each match
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid:
            first, sec = n.first2Hextets(ip.network)
            # add IPv6 data to address list
            ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec})
    return ipv4, ipv6

def get_route(device, address):
    # same as Cisco 9500
    return c9500.get_route(device, address)

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
    matches = re.finditer(r"^C\d+/\d+/\d+/\w+[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<operational>\d+)", device.response, re.M)
    for match in matches:
        count['online'] += int(match.group('operational'))
        count['total'] += int(match.group('total'))
    return count

## MAC Domain
def get_mac_domains(device):
    macs = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all mac-domains
    matches = re.finditer(r"^interface (?P<mac>Cable\d/0/\d{1,2})", device.config, re.M)
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
    # get mac domain config
    mac_config = ""
    match = re.search(r"^interface "+mac+r"\b.*\n"+
                                        r"( .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get description
    match = re.search(r"^ description (?P<description>[\S ]+)", mac_config, re.M)
    if match is not None:
        description = match.group('description')
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get mac domain config
    mac_config = ""
    match = re.search(r"^interface "+mac+r"\b.*\n"+
                                        r"( .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get DS
    match = re.search(r"^ downstream Integrated-Cable (?P<ds>\d/0/\d{1,2}) rf-channel", mac_config, re.M)
    if match is not None:
        DS = match.group('ds')
    # get US
    match = re.search(r"^ upstream \d+ Upstream-Cable (?P<us>\d/0/\d{1,2}) us-channel", mac_config, re.M)
    if match is not None:
        US = match.group('us')
    return DS, US

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get mac domain config
    mac_config = ""
    match = re.search(r"^interface "+mac+r"\b.*\n"+
                                        r"( .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # count DS and OFDM
    matches = re.finditer(r"^ downstream Integrated-Cable (?P<ds>\d/0/\d{1,2}) rf-channel ((?P<start>\d+)-(?P<end>\d+)|(?P<single>\d+))", mac_config, re.M)
    for match in matches:
        if match.group('single') is not None:
            counts['OFDM'] += 1
        else:
            counts['DS'] += int(match.group('end')) - int(match.group('start')) + 1
    # count US
    matches = re.finditer(r"^ upstream \d+ Upstream-Cable (?P<us>\d/0/\d{1,2}) us-channel \d+", mac_config, re.M)
    for match in matches:
        counts['US'] += 1
    return counts

def get_mac_cm_counts(device, DS):
    counts = {'online': 0, 'total': 0, 'percent': 100}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the cable-mac number
    number = None
    match = re.search(r"\d+/\d+/\d+", DS)
    if match is not None:
        number = f"C{match.group(0)}"
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        matches = re.finditer(r"^"+number+r"/\w{2}[ ]+(?P<total>\d+)[ ]+(?P<registered>\d+)[ ]+(?P<operational>\d+)[ ]+(?P<unregistered>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
        for match in matches:
            counts['total'] += int(match.group('total'))
            counts['online'] += int(match.group('operational'))
        if counts['total'] > 0:
            counts['percent'] = round((counts['online']/counts['total'])*100, 1)
    return counts

def get_mac_IP_interface(device, mac):
    interface = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get mac domain config
    mac_config = ""
    match = re.search(r"^interface "+mac+r"\b.*\n"+
                                        r"( .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get ip-bundle
    match = re.search(r"^ cable bundle (?P<interface>\d+)", mac_config, re.M)
    if match is not None:
        interface = "Bundle"+match.group('interface')
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
    matches = re.finditer(r"^interface (?P<interface>"+interface+r"(\.\d+)?)\n"+
                                            r"( .*\n)+", device.config, re.M)
    for match in matches:
        interface = match.group('interface')
        bundle_config = match.group(0)
        # get IPv4 addresses
        matches = re.finditer(r"^ ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
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

def get_mac_DSG_tunnels(device, mac):
    tunnels = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get mac domain config
    mac_config = ""
    match = re.search(r"^interface "+mac+r"\b.*\n"+
                                        r"( .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get all tunnel groups
    tgs = []
    matches = re.finditer(r"^ cable downstream dsg tg (?P<tg>\d+)", mac_config, re.M)
    for match in matches:
        tg = match.group('tg')
        if tg not in tgs:
            tgs.append(tg)
    # get all tunnels in tunnel groups
    for tg in tgs:
        matches = re.finditer(r"^cable dsg tunnel (?P<tunnel>\d+) mac-addr (?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4}) tg "+tg+r" clients (?P<client_list>\d+)", device.config, re.M)
        for match in matches:
            tunnels.append({'index': match.group('tunnel'), 'group': tg, 'client-list': {'id': match.group('client_list'), 'data':[]}, 'mac': match.group('mac')})
    # for each tunnel found
    for i in range(len(tunnels)):
        # collect additional tunnel information
        match = re.search(r"^cable dsg cfr (?P<classifier>\d+) dest-ip (?P<dest>(\d{1,3}\.){3}\d{1,3}) tunnel "+tunnels[i]['index']+r"( dest-port \d+ \d+)? priority \d+ src-ip (?P<src>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
        if match is not None:
            tunnels[i]['classifier'] = match.group('classifier')
            tunnels[i]['source'] = match.group('src')
            tunnels[i]['multicast'] = match.group('dest')
        # collect client-list data
        matches = re.finditer(r"^cable dsg client-list "+tunnels[i]['client-list']['id']+r" id-index (?P<index>\d+) (?P<type>\S+) (?P<value>\S+)", device.config, re.M)
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
                if client_list[0]['value'] == '700':
                    tunnel_type = 'ARRIS CA'
                elif client_list[0]['value'] == '701':
                    tunnel_type = 'ARRIS DSP'
                elif client_list[0]['value'] == '96B':
                    tunnel_type = 'DCAS CA'
                elif client_list[0]['value'] == 'E00':
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
                elif client_list[0]['value'] == '7D0':
                    tunnel_type = 'DCAS EPG'
        elif len(client_list) == 2:
            # if 'ca-system-id' is not first
            if client_list[0]['type'] != 'ca-system-id':
                # flip the list
                client_list = [client_list[1], client_list[0]]
            if client_list[0]['type'] == 'ca-system-id' and client_list[1]['type'] == 'mac-addr':
                if client_list[0]['value'] == 'E00':
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
    # get video config
    video_config = ""
    match = re.search(r"^cable video\n"+
                                        r"(  .*\n)+", device.config, re.M)
    if match is not None:
        video_config = match.group(0)
    # get sdg
    match = re.search(r"^  service-distribution-group (?P<sdg>[\S ]+) id \d+\n"+
                                        r"    rf-port integrated-cable "+DS, video_config, re.M)
    if match is None:
        return interface
    sdg = match.group('sdg').replace('(',r"\(").replace(')',r"\)").replace('.',r"\.").replace('[',r"\[").replace(']',r"\]")
    # get vcg
    match = re.search(r"^    vcg (?P<vcg>[\S ]+) sdg "+sdg, video_config, re.M)
    if match is None:
        return interface
    vcg = match.group('vcg').replace('(',r"\(").replace(')',r"\)").replace('.',r"\.").replace('[',r"\[").replace(']',r"\]")
    # get LED id
    match = re.search(r"^  logical-edge-device [\S ]+ id (?P<led>\d+)\n"+
                                        r"(    .*\n)+"+
                                        r"      vcg "+vcg, video_config, re.M)
    if match is None:
        return interface
    interface = "logical-edge-device id "+match.group('led')
    return interface

def get_mac_video(device, DS):
    video = {}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get video config
    video_config = ""
    match = re.search(r"^cable video\n"+
                      r"(  .*\n)+", device.config, re.M)
    if match is not None:
        video_config = match.group(0)
    # get sdg
    match = re.search(r"^  service-distribution-group (?P<sdg>[\S ]+) id \d+\n"+
                      r"    rf-port integrated-cable "+DS, video_config, re.M)
    if match is None:
        return {}
    sdg = match.group('sdg').replace('(',r"\(").replace(')',r"\)").replace('.',r"\.").replace('[',r"\[").replace(']',r"\]")
    # get vcg
    match = re.search(r"^    vcg (?P<vcg>[\S ]+) sdg "+sdg, video_config, re.M)
    if match is None:
        return {}
    vcg = match.group('vcg').replace('(',r"\(").replace(')',r"\)").replace('.',r"\.").replace('[',r"\[").replace(']',r"\]")
    # get vcg config
    match = re.search(r"^  virtual-carrier-group "+vcg+r" id \d+\n"+
                      r"(    .*\n)+", video_config, re.M)
    if match is None:
        return {}
    vcg_config = match.group(0)
    # get RF-channels, TSIDs, and virtual-channels from VCG config
    match = re.search(r"^    rf-channel (?P<rf_chan_start>\d+)-(?P<rf_chan_end>\d+) tsid (?P<tsid_start>\d+)-(?P<tsid_end>\d+)"+
                      r" output-port-number (?P<virt_start>\d+)-(?P<virt_end>\d+)", vcg_config, re.M)
    if match is None:
        return {}
    start_rf_chan = match.group('rf_chan_start')
    end_rf_chan = match.group('rf_chan_end')
    video['num_channels'] = int(end_rf_chan) - int(start_rf_chan) + 1
    #video['start_channel'] = int(match.group('virt_start'))
    video['start_tsid'] = int(match.group('tsid_start'))
    virt_start_chan = int(match.group('virt_start'))
    video['qam_port'] = int(virt_start_chan/32)+1
    video['start_channel'] = virt_start_chan%32
    # get LED config
    match = re.search(r"^  logical-edge-device (?P<name>[\S ]+) id (?P<led>\d+)\n"+
                      r"(    .*\n)+"+
                      r"      vcg "+vcg+r".*\n"+
                      r"(    .*\n)*", video_config, re.M)
    if match is None:
        return {}
    video['led_id'] = match.group('led')
    led_config = match.group(0)
    # get MGMT IP from LED config
    match = re.search(r"^      mgmt-ip (?P<ip>(\d{1,3}\.){3}\d{1,3})", led_config, re.M)
    if match is None:
        return {}
    video['mgmt_ip'] = match.group('ip')
    # get ingest IP and port from LED config
    match = re.search(r"^      virtual-edge-input-ip (?P<ip>(\d{1,3}\.){3}\d{1,3}) input-port-number (?P<port>\d+)", led_config, re.M)
    if match is None:
        return {}
    video['ingest_ip'] = match.group('ip')
    video['ingest_port'] = match.group('port')
    # get Integrated-Cable config
    match = re.search(r"^controller Integrated-Cable "+DS+r"\n"+
                      r"( .*\n)+", device.config, re.M)
    if match is None:
        return {}
    ds_config = match.group(0)
    # get starting frequency from Integrated-Cable config
    match = re.search(r"^ rf-chan "+start_rf_chan+r" \d+\n"+
                      r"  type VIDEO\n"+
                      r"  frequency (?P<start_freq>\d{3})\d+", ds_config, re.M)
    if match is None:
        return {}
    video['start_freq'] = int(match.group('start_freq'))
    return video

############################################################
############### CM #########################################
############################################################
def get_modem(device, modem, query_value, query_type):
    cmd_sets = {
                'MAC':  [
                         f'show cable modem {query_value}'
                        ],
                'IPv4': [
                         f'show cable modem {query_value}'
                        ],
                'IPv6': [
                         f'show cable modem {query_value}'
                        ]
               }
    # get commands to run
    cmds = None
    for key, cmd_set in cmd_sets.items():
        if key.lower() in query_type.lower():
            cmds = cmd_set
    # declare set of valid CM states
    states = ['online', 'init', 'reject', 'expire', 'resetting', 'offline']
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
        match = re.search(r"^(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<ip>((\d{1,3}\.){3}\d{1,3})|-+)[ ]+"+
                          r"C\d{1,2}/\d/\d{1,2}\S*[ ]+(?P<state>\S*"+states_string+r"\S*)", device.response, re.M|re.I)
        if match is not None:
            modem.output = device.response
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
                cmd = f"show cable modem {modem.mac} ipv6"
                device.get_response(['', cmd])
                modem.output += '\n'+device.response
                match = re.search(r"[\da-fA-F:]+:[\da-fA-F:]+", device.response)
                if match is not None:
                    modem.ipv6 = match.group(0).lower()
            break
#    if match is None:
 #       modem.output = modem.output[1:]
    return modem

