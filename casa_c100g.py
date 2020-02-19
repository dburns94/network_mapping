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
    cmd_set = {"MAC":  ["show cable modem "+queryValue,
                                            "show cable modem cpe | include "+queryValue
                                          ],
                          "IPv4": ["show cable modem "+queryValue+" mac",
                                            "show cable modem "+queryValue
                                          ],
                          "IPv6": ["show cable modem "+queryValue+" mac",
                                            "show cable modem "+queryValue
                                          ]
                        }
    # declare set of valid CM states
    states = [" online", "init", queryValue.lower()]

    # send commands
    for cmd in cmd_set[queryType]:
        output = []
        # execute the command
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # for each line in the output
        for line in lines[1:-1]:
            # keep the output for later use
            if "Offset" not in line and "Said" not in line:
                output.append(line)
            # make the line lowercase
            line = line.lower()
            # for each valid CM state
            for state in states:
                # if the modem is in that state
                if state in line and "offline" not in line:
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
        elif col.get("CM MAC Address") != None:
            # for each row in the table
            for row in table[1:]:
                # get the value in the MAC address column
                mac = row[col["CM MAC Address"]]
                # if this was a valid MAC address
                if n.validMAC(mac):
                    # store the MAC as the CM MAC
                    cm_mac = mac
                    break
    return [online, cm_mac]

def getCM_phy(session, expec, cm_mac):
    phy = {"US SNR": "", "DS SNR": "", "US Power TX": "", "US Power RX": "", "DS Power": ""}
    associations = {"US SNR": "USSNR", "DS SNR": "DSSNR", "DS Power": "DSPwr"}
    # send command
    cmd = "show cable modem "+cm_mac+" phy"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # only keep the output needed
    output = []
    for line in lines[1:-1]:
        if "Offset" not in line:
            output.append(line)
    # parse the output as a table
    [col, table] = ps.parseTable(output)
    # add the data that is present
    for key, value in associations.items():
        if col.get(value) != None:
            phy[key] = table[1][col[value]]
    # US power TX and RX are in a single column
    if col.get("USPwr(dB)") != None:
        value = ps.minSpaces(table[1][col["USPwr(dB)"]]).split(" ")
        if len(value) > 1:
            phy["US Power TX"] = value[0]
            phy["US Power RX"] = value[1]
    return phy

def getCM_ip(session, expec, cm_mac):
    cm_ip = ""
    # send command
    cmd = "show cable modem "+cm_mac
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # only keep the output needed
    output = []
    for line in lines[1:-1]:
        if "Offset" not in line:
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
                # store the IP as the CM IP
                cm_ip = ip
                break
    # if the CM has an IPv6 address
    if cm_ip == "0.0.0.0":
        cm_ip = ""
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
    cmd = "show cable modem "+cm_mac+" verbose | include ^MAC\sDomain"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    # search the output for the line containing the MAC domain
    for line in lines[1:-1]:
        if "MAC Domain" in line:
            section = line.replace(" ","").split(":")
            cm_domain = "docsis-mac "+section[1]
    return cm_domain

def testPing(session, expec, ip, count, fail_threshold):
    success = True
    # initialize counts
    passed = 0
    failed = 0
    # create ping command
    if ":" in ip:
        cmd = "ping6 repeat 1 timeout 1 "+ip
    else:
        cmd = "ping repeat 1 timeout 1 "+ip
    # for the number of pings
    for i in range(count):
        # send one ping
        lines = p_ext.sendCMD(session, cmd, expec, 10)
        # look at each line in the output
        for line in lines[1:-1]:
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
    cmd = "page-off"
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
    cmd = "show version | include Image"
    output = p_ext.getOutput(session, cmd, expec, timeout=10)
    pattern = re_ext.compile(r"File\ name:.+rel(\S+)")
    match = pattern.search(output)
    if match:
        version = match.group(1)
    return version

# cmts-status info gathering
#def ipConnectivity(device, ips, iphelper):
 #   results = []
  #  ip_type = ''
   # for ip in ips:
    #    sys.stdout.write('.')
     #   # determine the IP type
      #  if ':' in ip['address']:
       #     ip_type = '6'
        # get the response
#        cmd = f"ping{ip_type} repeat 3 source {ip['address'].split('/')[0]} {iphelper}"
 #       device.get_response(cmd)
  #      # parse the response
   #     lines = device.response.split('\n')
    #    for i in lines[1:]:
     #       if "packets transmitted" in i:
      #          i = ps.minSpaces(i)
       #         transmitted = int(ps.returnN(i,0))
        #        recieved = int(ps.returnN(i,3))
         #       results.append({'ip': ip['address'], 'recieved': recieved, 'transmitted': transmitted})
#    return results

def ipConnectivity(device, ips, iphelper):
    pings = []
    # for each IP
    for ip in ips:
        sys.stdout.write('.')
        # determine the IP type
        ip_type = '6 ' if ':' in ip['address'] else ''
        # send pings
        cmd = f"ping{ip_type} repeat 3 source {ip['address'].split('/')[0]} {iphelper}"
        device.get_response(cmd, timeout=15)
        # get the pings counts
        match = re.search(r"^(?P<sent>\d+)[ ]+packets transmitted, (?P<received>\d+) packets received", device.response, re.M)
        if match is not None:
            pings.append({'ip': ip['address'], 'recieved': match.group('received'), 'transmitted': match.group('sent')})
    return pings

#def channelStatus(device, mac, DS, US):
 #   dsStatus = []
  #  usStatus = []
   # cmd = f"show interface {mac} topology"
    #device.get_response(cmd)
    # parse the response
#    lines = device.response.split('\n')
 #   for i in lines[1:]:
  #      i = ps.minSpaces(i)
   #     if DS+"/" in i and len(i.split(' ')) > 3:
    #        sys.stdout.write('.')
     #       try:
      #          power = str(float(ps.returnN(i,7))/10)
       #     except:
        #        power = '-'
         #   dsStatus.append({'channel': ps.returnN(i,0), 'status': ps.returnN(i,3), 'frequency': ps.returnN(i,5)[0:3]+" MHz", 'power': power+" dBmV"})
#        elif US+"." in i and len(i.split(' ')) > 3:
 #           sys.stdout.write('.')
  #          frequency = float(ps.returnN(i,5))/1000000
   #         width = float(ps.returnN(i,6))/1000000
    #        startFreq = str(round(frequency - width/2,3))
     #       endFreq = str(round(frequency + width/2,3))
      #      usStatus.append({'channel': ps.returnN(i,0), 'status': ps.returnN(i,3), 'frequency': startFreq+"-"+endFreq+" MHz", 'power': '-'})
#    return [dsStatus, usStatus]

def channelStatus(device, mac, DS, US):
    ds_status = []
    us_status = []
    # get cable-macs output
    if getattr(device, 'mac_interface_status', None) is None:
        cmd = "show interface docsis-mac topology"
        device.mac_interface_status = device.get_response(cmd)
    # get DOCSIS channels
    matches = re.finditer(r"^(?P<channel>"+DS+r"/\d{1,2})[ ]+\d+[ ]+\d+[ ]+(?P<status>\S+)[ ]+(?P<annex>\S+)[ ]+"+
                          r"(?P<freq>\d{3})0{6}[ ]+\S+[ ]+(?P<power>\d+)", device.mac_interface_status, re.M)
    for match in matches:
        sys.stdout.write('.')
        ds_status.append({'channel': match.group('channel'), 'status': match.group('status'), 'frequency': match.group('freq'), 'power': str(float(match.group('power'))/10)})
    # get US channels
    matches = re.finditer(r"^(?P<channel>"+US+r"\.\d{1,2}/\d{1,2})[ ]+\d+[ ]+\d+[ ]+(?P<status>\S+)[ ]+\S+[ ]+"+
                          r"(?P<freq>\d+)0{5}[ ]+(?P<width>\d+)0{5}[ ]+", device.mac_interface_status, re.M)
    for match in matches:
        sys.stdout.write('.')
        center_freq = float(match.group('freq'))/10
        width = float(match.group('width'))/10
        bottom = round(center_freq-width/2,1)
        top = round(center_freq+width/2,1)
        us_status.append({'channel': match.group('channel'), 'status': match.group('status'), 'frequency': f"{bottom}-{top}", 'power': '-'})
    return ds_status, us_status

#def getMCounts(device, multicasts):
 #   counts = []
  #  for i in multicasts:
   #     getCount = False
    #    # get the response
     #   cmd = f"show ip mroute {i['multicast']} | include {i['source']}|pkts"
      #  device.get_response(cmd)
       # # parse the response
        #lines = device.response.split('\n')
#        for j in lines[1:]:
 #           if i['source'] in j:
  #              getCount = True
   #         if "pkts" in j and getCount:
    #            sys.stdout.write(".")
     #           j = ps.minSpaces(j)
      #          counts.append({'multicast': {'multicast': i['multicast'], 'source': i['source']}, 'count': int(ps.returnN(j,3)), 'type': i['type'], 'tunnel': i['tunnel']})
       #         break
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
        match = re.search(r"^\("+src+r", "+group+r"\), .+\n"+
                          r"(  .+\n)*"+
                          r"  .* (?P<packets>\d+) pkts, ", device.mcounts, re.M)
        if match is not None:
            counts.append({'multicast': {'multicast': mcast['multicast'], 'source': mcast['source']}, 'count': int(match.group('packets')),
                           'type': mcast['type'], 'tunnel': mcast['tunnel']})
    return counts

#def getDSGcounts(device, DSinterface, mac, tunnels):
 #   count = []
  #  # get the response
   # cmd = f"show dsg statistics traffic | include {DSinterface}/0"
    #device.get_response(cmd)
    # parse the response
#    lines = device.response.split('\n')
 #   for i in lines[1:-1]:
  #      sys.stdout.write(".")
   #     i = ps.minSpaces(i)
    #    count.append({'tunnel': ps.returnN(i,1), 'count': int(ps.returnN(i,3))})
    # convert replication to tunnel number
#    cmd = f"show multicast replication {mac}"
 #   device.get_response(cmd)
  #  # parse the response
   # lines = device.response.split('\n')
    #tunnel = ""
#    for i in range(len(count)):
 #       for j in lines[1:]:
  #          j = ps.minSpaces(j)
   #         if "<239." in j:
    #            tunnel = "Unknown"
     #           multicast = j[1:j.find(",")]
      #          for k in tunnels:
       #             if multicast == k['multicast']:
        #                tunnel = k['tunnel']
         #               break
          #  elif len(j.split(' ')) >3:
           #     if ps.returnN(j,2) == count[i]['tunnel']:
            #        count[i]['tunnel'] = tunnel
             #       tunnel = ""
              #      break
#    for i in range(len(count)):
 #       for j in tunnels:
  #          if j['tunnel'] == count[i]['tunnel']:
   #             count[i]['type'] = j['type']
    #return count

def getDSGcounts(device, DS, mac, tunnels):
    counts = []
    # get DSG counts
    if getattr(device, 'dsg_counts', None) is None:
        cmd = "show dsg statistics traffic"
        device.dsg_counts = device.get_response(cmd)
    # get each replication from all channels
    replications = []
    matches = re.finditer(r"^\d+[ ]+(?P<replication>\d+)[ ]+"+DS+r"/\d{1,2}[ ]+(?P<packets>\d+)", device.dsg_counts, re.M)
    for match in matches:
        replications.append([match.group('replication'), int(match.group('packets'))])
    # get all replication multicasts
    if getattr(device, 'mcast_replications', None) is None:
        cmd = "show multicast replication"
        device.mcast_replications = device.get_response(cmd)
    # for each tunnel
    for tunnel in tunnels:
        sys.stdout.write('.')
        # convert IPs to raw text
        src = tunnel['source'].replace('.',r"\.")
        group = tunnel['multicast']
        # get all replication section
        match = re.search(r"^<"+group+r", "+src+r">\n"+
                          r"(  .*\n)+", device.mcast_replications, re.M)
        if match is not None:
            match_found = False
            # get all replication numbers
            matches = re.finditer(r"^  qam \d+[ ]+(?P<replication>\d+)[ ]+", match.group(0), re.M)
            for match in matches:
                # for each replication found earlier
                for replication in replications:
                    if match.group('replication') == replication[0]:
                        match_found = True
                        counts.append({'tunnel': tunnel['tunnel'], 'count': replication[1], 'type': tunnel['type']})
                        break
                # only keep 1 count per tunnel
                if match_found:
                    break
    return counts

#def getSNR(device, US):
 #   snr = []
  #  # get the response
   # cmd = f"show upstream {US} signal-quality | exclude \s0.0"
    #device.get_response(cmd)
    # parse the response
#    lines = device.response.split('\n')
 #   for i in lines[1:]:
  #      if US+"." in i:
   #         i = ps.minSpaces(i)
    #        snr.append({'channel': i[0:i.find("/")+4:1], 'snr': float(ps.returnN(i,1))})
#    return snr

def getSNR(device, US):
    snr_readings = []
    # get noise readings
    if getattr(device, 'snr', None) is None:
        cmd = "show upstream signal-quality"
        device.snr = device.get_response(cmd)
    # get each channels SNR
    matches = re.finditer(r"^(?P<channel>"+US+r"\.\d{1,2}/\d{1,2})[ ]+(?P<snr>\d+(\.\d+)?)", device.snr, re.M)
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
    #cmd = f"show cable modem {mac} summary"
#    device.get_response(cmd)
 #   # parse the response
  #  lines = device.response.split('\n')
   # for i in lines:
    #    if begin+"   " in i:
     #       i = ps.minSpaces(i)
      #      count['online'] = int(ps.returnN(i,3))
       #     count['total'] = int(ps.returnN(i,1))
#    return count

def cmCount(device, US):
    counts = {'online': 0, 'total': 0}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the modem counts
    matches = re.finditer(r"^"+US+r"\.\d+/\d+[ ]+\d+[ ]+(?P<total>\d+)[ ]+(?P<active>\d+)[ ]+(?P<online>\d+)[ ]+(?P<secondary>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
    for match in matches:
        counts['total'] += int(match.group('total'))
        counts['online'] += int(match.group('online'))
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
    cmd = "clear cable modem offline"
    lines = p_ext.sendCMD(session, cmd, expec, 20)

###########################################
# network functions
###########################################
def getAllIPs(session, expec):
    ipv4 = []
    # get list of interfaces that are up/up
    up_interfaces = []
    cmd = "show ip interface brief | exclude down|:"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[3:-1]:
        lineWords = ps.minSpaces(line).split(" ")
        interface = lineWords[0]+" "+lineWords[1]
        if interface not in up_interfaces:
            up_interfaces.append(interface)
    # get IPv4s from up/up interfaces
    cmd = "show interface | include ^interface\s[elixgd]|ip\saddress"
    lines = p_ext.sendCMD(session, cmd, expec, 20)
    i = 1
    while i < len(lines)-2:
        if "interface" in lines[i]:
            # get interface
            interface = ps.minSpaces(lines[i].replace("interface",""))
            # if this is an up/up interface
            if interface in up_interfaces:
                # while the next line is an IPv4 address
                while "ip address" in lines[i+1]:
                    # get interface IPv4 address and subnet
                    lines[i+1] = ps.minSpaces(lines[i+1])
                    ip = ps.returnN(lines[i+1], 2)
                    subnet = str(n.mask_prefix(ps.returnN(lines[i+1], 3)))
                    network = n.nthIPv4(ip+"/"+subnet, 0)
                    # add IPv4 data to address list
                    ipv4.append({"Interface": interface, "Network": network, "Assigned": ip, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
                    i += 1
        i += 1
    # get IPv4 video IPs
    cmd = "show interface video | include ^interface|^\s\sip\saddress"
    lines = p_ext.sendCMD(session, cmd, expec, 20)
    i = 1
    while i < len(lines)-2:
        if "interface" in lines[i]:
            # get interface
            interface = ps.minSpaces(lines[i].replace("interface",""))
            # if next line has an IP address
            if "ip address" in lines[i+1]:
                addressWords = ps.minSpaces(lines[i+1]).split(" ")
                ip = addressWords[2]
                subnet = str(n.mask_prefix(addressWords[3]))
                network = n.nthIPv4(ip+"/"+subnet, 0)
                # add IPv4 data to address list
                ipv4.append({"Interface": interface, "Network": network, "Assigned": ip, "First": n.v4_dec(network), "Last": n.v4_dec(n.nthIPv4(network, "last"))})
                i += 1
        i += 1
    # get IPv6 interfaces
    ipv6 = []
    cmd = "show ipv6 interface | include is\sup,\sline\sprotocol|link-local\saddress|,\ssubnet\sis"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    i = 1
    while i < len(lines)-3:
        if "line protocol" in lines[i]:
            if "address" in lines[i+1]:
                # get interface
                lineWords = ps.minSpaces(lines[i]).split(" ")
                interface = lineWords[0]+" "+lineWords[1]
                # get link-local address
                linkLocal = ""
                if "no link-local" not in lines[i+1]:
                    linkWords = ps.minSpaces(lines[i+1]).split(" ")
                    for j in range(len(linkWords)):
                        if linkWords[j] == "link-local":
                            linkLocal = linkWords[j+2].lower()
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
    cmd = "show running-config | include ^ipv6\sroute"
    lines = p_ext.sendCMD(session, cmd, expec, 10)
    for line in lines[1:-1]:
        lineWords = ps.minSpaces(line).split(" ")
        # get the network
        network = lineWords[2]
        # get the interface
        interface = lineWords[3]
        # if this is a null route, make the interface a prefix-delegation
        if "null" in interface:
            interface = "PD"
        if network != "::/0":
            # calculate first two hexadecimals
            [first, sec] = n.first2Hextets(network)
            # add IPv6 data to address list
            ipv6.append({"Interface": interface, "Network": network, "Assigned": network.split("/")[0], "First Hex": first, "Sec Hex": sec, "Link-Local": ""})
    return [ipv4, ipv6]

def getRoute(session, expec, address):
    ### same function as CASA C100G and ADTRAN 9504N ###
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
                if "*" in line:
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
                    route["Interface"] = routeWords[3]
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

###############
##### NEW #####
###############
import re

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show version | include Image"
    device.get_response(cmd)
    # parse the response
    match = re.search(r"^Image booted from: .* File name: .*rel(?P<version>\S+)", device.response, re.M)
    if match is not None:
        version = match.group('version').strip()
    return version

############################################################
############### Networking #################################
############################################################
def get_ips(device, link_local=True):
    ipv4 = []
    ipv6 = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get all IP interfaces
    #matches = re.finditer(r"^interface (?P<interface>((eth|(x)?gige) \d+/\d+|(loopback|video) \d+|ip-bundle \d+(\.\d+)?|))\n"+
    matches = re.finditer(r"^interface (?P<interface>(xgige \d+/\d+|(loopback|video) \d+|ip-bundle \d+(\.\d+)?|))\n"+
                          r"(  .+\n)+", device.config, re.M)
    # for each IP interface
    for match in matches:
        # get the interface name
        interface = match.group('interface')
        # get IPv4 addresses
        ip_matches = re.finditer(r"^  ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(?P<netmask>(\d{1,3}\.){3}\d{1,3})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'), netmask=ip_match.group('netmask'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv4 data to address list
                #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
                ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
        # get IPv6 addresses
        ip_matches = re.finditer(r"^  ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", match.group(0), re.M)
        for ip_match in ip_matches:
            # get the IP address
            ip = n.IP(ip_match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # calculate the first three half-hextets
                first_hex, sec_hex, third_hex = ip.first_three
                # add IPv6 data to address list
                #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
                ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    if link_local:
        # get IPv6 link-local addresses
        cmd = "show ipv6 interface | include protocol|link-local"
        device.get_response(cmd)
        matches = re.finditer(r"^(?P<interface>((eth|xgige) \d+/\d+|(loopback|video) \d+|ip-bundle \d+(\.\d+)?|))\n"+
                              r"   IPv6 is enabled, link-local address (?P<ip>[\da-fA-F:]+/\d{1,3})", device.response, re.M)
        for match in matches:
            # get the interface name
            interface = match.group('interface')
            # get the IP address
            ip = n.IP(match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add the address to the previous entries
                for i in range(len(ipv6)):
                    if ipv6[i]['Interface'] == interface:
                        ipv6[i]['Link-Local'] = ip.addr
#                    if ipv6[i]['interface'] == interface:
 #                       ipv6[i]['link_local'] = ip.addr
    # get IPv6 aggregate routes
    interface = 'PD'
    matches = re.finditer(r"^ipv6 route (?P<ip>[\da-fA-F:]+/\d{1,3}) null0", device.config, re.M)
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
    # get IPv4 addresses
#    cmd = "show interface"
 #   device.get_response(cmd)
  #  # search the output
   # pattern = re.compile(r"^interface (?P<interface>[\S ]+)\n"+
    #                     r"((  )+.*\n)*"+
     #                    r"(  ip address (\d{1,3}\.){3}\d{1,3}[ ]+(\d{1,3}\.){3}\d{1,3}.*\n)+", re.M)
#    matches = pattern.finditer(device.response)
 #   # for each match
  #  pattern = re.compile(r"ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(?P<netmask>(\d{1,3}\.){3}\d{1,3})")
   # for match in matches:
    #    interface = match.group('interface')
     #   # get all IPs
      #  all_ips = pattern.finditer(match.group(0))
       # for each_ip in all_ips:
        #    ip = n.IP(each_ip.group('ip'), netmask=each_ip.group('netmask'))
         #   if ip.valid:
          #      # add IPv4 data to address list
           #     ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get video interfaces
#    matches = re.finditer(r"^interface (?P<interface>video \d+)\n"+
 #                         r"(  .+\n)*"+
  #                        r"  ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})[ ]+(?P<netmask>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
   # for match in matches:
    #    interface = match.group('interface')
     #   ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
      #  if ip.valid:
       #     # add IPv4 data to address list
        #    ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get IPv6 addresses
#    cmd = "show ipv6 interface"
 #   device.get_response(cmd)
  #  # search the output
   # pattern = re.compile(r"^(?P<interface>(loopback|xgige|ip-bundle) \d+(/\d+)?(\.\d+)?) is (?P<state>[\S ]+), line protocol is (?P<proto>\S+)\n"+
    #                     r"[ ]+IPv6 is enabled, (no link-local address|link-local address (?P<link_local>[\da-fA-F:]+))\n"+
     #                    r"(?P<spaces>[ ]+)Global unicast address\(es\):\n"+
      #                   r"(?P<ips>((?P=spaces)[ ]+[\da-fA-F:]+,.*\n)+)", re.M)
#    matches = pattern.finditer(device.response)
 #   # for each match
  #  pattern = re.compile(r"(?P<ip>[\da-fA-F:]+), subnet is [\da-fA-F:]+/(?P<prefix>\d{1,3})")
   # for match in matches:
    #    interface = match.group('interface')
     #   if match.group('link_local') is None:
      #      link_local = None
       # else:
        #    link_local = n.IP(match.group('link_local'))
         #   if not link_local.valid:
          #      continue
        # get all interface IPs
#        all_ips = pattern.finditer(match.group('ips'))
 #       for each_ip in all_ips:
  #          ip = n.IP(each_ip.group('ip')+'/'+each_ip.group('prefix'))
   #         if ip.valid:
    #            first, sec = n.first2Hextets(ip.network)
     #           if link_local is not None:
      #              # add IPv6 data to address list
       #             ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec, 'Link-Local': link_local.addr})
        #        else:
         #           # add IPv6 data to address list
          #          ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec})
    # get static routes
#    interface = 'PD'
 #   matches = re.finditer(r"^ipv6 route (?P<ip>[\da-fA-F:/]+) null", device.config, re.M)
  #  # for each match
   # for match in matches:
    #    ip = n.IP(match.group('ip'))
     #   if ip.valid:
      #      first, sec = n.first2Hextets(ip.network)
       #     # add IPv6 data to address list
        #    ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first, 'Sec Hex': sec})
    return ipv4, ipv6

def get_route(device, address):
    route = {'Network': '', 'Process': '', 'Next-Hop': '', 'Interface': '', 'Child-Hop': ''}
    # if this is an IPv4 network
    if address.type == 4:
        # get route
        cmd = "show ip route "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>(\d{1,3}\.){3}\d{1,3}/\d{1,3}).*\n"+
                                            r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                            r"([ ]+.*\n)*"+
                                            r"[ ]+\*[ ]+(?P<next_hop>(\d{1,3}\.){3}\d{1,3}|is directly connected),( via)? (?P<interface>\S+)", device.response, re.M)
        if match is not None:
            route['Network'] = match.group('network')
            route['Next-Hop'] = match.group('next_hop').lower()
            route['Process'] = match.group('process')
            if route['Process'] == 'connected':
                route['Next-Hop'] = address.addr
            route['Interface'] = match.group('interface')
        # if the device has no route
        elif re.search(r"Network[ ]+not[ ]+in[ ]+table", device.response) is not None:
            # collect the default route
            route = get_route(device, n.IP('0.0.0.0/0'))
    # if this is an IPv6 network
    else:
        # get the route
        cmd = "show ipv6 route "+address.addr
        device.get_response(cmd)
        # parse route
        match = re.search(r"^Routing entry for (?P<network>\S+)\n"+
                                            r"[ ]+Known via \"(?P<process>[\S ]+)\", .*\n"+
                                            r"([ ]+.*\n)+?"+
                                            r"[ ]+\*[ ]+(via )?(?P<next_hop>[\da-fA-F:]+|directly connected), (?P<interface>\S+)", device.response, re.M)
        if match is not None:
            route['Network'] = match.group('network')
            route['Next-Hop'] = match.group('next_hop').lower()
            route['Process'] = match.group('process')
            if route['Process'] == 'connected':
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
    matches = re.finditer(r"^\d+/\d+\.\d+/\d+[ ]+\d+[ ]+(?P<total>\d+)[ ]+(?P<active>\d+)[ ]+(?P<registered>\d+)", device.response, re.M)
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
    matches = re.finditer(r"^interface docsis-mac[ ]+(?P<mac>\d+)", device.config, re.M)
    for match in matches:
        mac = "docsis-mac "+match.group('mac')
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
    # get MAC domain config
    mac = mac.split(' ')[1]
    mac_config = ""
    match = re.search(r"^interface docsis-mac[ ]+"+mac+r"\b.*\n"+
                                        r"(  .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get description
    match = re.search(r"^  description \"(?P<description>[\S ]+)\"", mac_config, re.M)
    if match is not None:
        description = match.group('description')
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get MAC domain config
    mac = mac.split(' ')[1]
    mac_config = ""
    match = re.search(r"^interface docsis-mac[ ]+"+mac+r"\b.*\n"+
                                        r"(  .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get DS
    match = re.search(r"^  downstream \d+ interface qam (?P<ds>\d{1,2}/\d{1,2})/\d{1,2}", mac_config, re.M)
    if match is not None:
        DS = match.group('ds')
    # get US
    match = re.search(r"^  upstream \d+ interface upstream (?P<us>\d{1,2}/\d{1,2})\.\d{1,2}/\d{1,2}", mac_config, re.M)
    if match is not None:
        US = match.group('us')
    return DS, US

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get MAC domain config
    mac = mac.split(' ')[1]
    mac_config = ""
    match = re.search(r"^interface docsis-mac[ ]+"+mac+r"\b.*\n"+
                                        r"(  .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # count DS
    matches = re.finditer(r"^  downstream \d+ interface qam (\d{1,2}/){2}\d{1,2}", mac_config, re.M)
    for match in matches:
        counts['DS'] += 1
    # count OFDM
    matches = re.finditer(r"^  downstream \d+ interface ofdm (\d{1,2}/){2}\d{1,2}", mac_config, re.M)
    for match in matches:
        counts['OFDM'] += 1
    # count US
    matches = re.finditer(r"^  upstream \d+ interface upstream \d{1,2}/\d{1,2}\.\d{1,2}/\d{1,2}", mac_config, re.M)
    for match in matches:
        counts['US'] += 1
    return counts

def get_mac_cm_counts(device, US):
    counts = {'online': 0, 'total': 0, 'percent': 100}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the modem counts
    matches = re.finditer(r"^"+US+r"\.\d+/\d+[ ]+\d+[ ]+(?P<total>\d+)[ ]+(?P<active>\d+)[ ]+(?P<online>\d+)[ ]+(?P<secondary>\d+)[ ]+(?P<offline>\d+)", device.modem_summary, re.M)
    for match in matches:
        counts['total'] += int(match.group('total'))
        counts['online'] += int(match.group('online'))
    if counts['total'] > 0:
        counts['percent'] = round((counts['online']/counts['total'])*100, 1)
    return counts

def get_mac_IP_interface(device, mac):
    interface = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    mac = mac.split(' ')[1]
    mac_config = ""
    match = re.search(r"^interface docsis-mac[ ]+"+mac+r"\b.*\n"+
                                        r"(  .*\n)+", device.config, re.M)
    if match is not None:
        mac_config = match.group(0)
    # get ip-bundle
    match = re.search(r"^  ip bundle (?P<interface>\d+)", mac_config, re.M)
    if match is not None:
        interface = "ip-bundle "+match.group('interface')
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
                                            r"(  .*\n)+", device.config, re.M)
    for match in matches:
        interface = match.group('interface')
        bundle_config = match.group(0)
        # get IPv4 addresses
        matches = re.finditer(r"^  ip address (?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<netmask>(\d{1,3}\.){3}\d{1,3})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'), netmask=match.group('netmask'))
            if ip.valid:
                ipv4.append({'interface': interface, 'address': str(ip)})
        # get IPv4 helpers
        matches = re.finditer(r"^  cable helper-address (?P<ip>(\d{1,3}\.){3}\d{1,3})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'))
            if ip.valid and ip.addr not in ipv4helper:
                ipv4helper.append(ip.addr)
        # get IPv6 addresses
        matches = re.finditer(r"^  ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", bundle_config, re.M)
        for match in matches:
            ip = n.IP(match.group('ip'))
            if ip.valid:
                ipv6.append({'interface': interface, 'address': str(ip)})
        # get IPv6 helpers
        matches = re.finditer(r"^  cable helper-ipv6-address (?P<ip>[\da-fA-F:]+)", bundle_config, re.M)
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
    matches = re.finditer(r"^dsg tunnel-group (?P<tg>\d+)\n"+
                                                r"(  .+\n)*"+
                                                r"  channel \d+[ ]+qam "+DS+r"/\d{1,2}", device.config, re.M)
    for match in matches:
        tg = match.group('tg')
        if tg not in tgs:
            tgs.append(tg)
    # get all tunnels in tunnel groups
    for tg in tgs:
        matches = re.finditer(r"^dsg tunnel (?P<tunnel>\d+)\n"+
                                                    r"  group "+tg+r"\n"+
                                                    r"(  dst-address (?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})\n)?"+
                                                    r"(  client-list (?P<client_list>\d+)\n)?"+
                                                    r"(  classifier (?P<classifier>\d+) \d+ (?P<src>(\d{1,3}\.){3}\d{1,3})/\d{1,2} (?P<dest>(\d{1,3}\.){3}\d{1,3}))?", device.config, re.M)
        for match in matches:
            tunnels.append({'index': match.group('tunnel'), 'group': tg, 'client-list': {'id': match.group('client_list'), 'data':[]}, 'mac': match.group('mac'), 
                                            'classifier': match.group('classifier'), 'source': match.group('src'), 'multicast': match.group('dest')})
    # for each tunnel found
    for i in range(len(tunnels)):
        # collect client-list data
        matches = re.finditer(r"^dsg client-list "+tunnels[i]['client-list']['id']+r" client (?P<index>\d+)[ ]+id-type (?P<type>\S+)[ ]+id-value (?P<value>\S+)", device.config, re.M)
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
            elif client_list[0]['type'] == 'caSysId':
                if client_list[0]['value'] == '1792':
                    tunnel_type = 'ARRIS CA'
                elif client_list[0]['value'] == '1793':
                    tunnel_type = 'ARRIS DSP'
                elif client_list[0]['value'] == '2411':
                    tunnel_type = 'DCAS CA'
                elif client_list[0]['value'] == '3584':
                    tunnel_type = 'Cisco Hub'
            elif client_list[0]['type'] == 'appId':
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
            # if 'caSysId' is not first
            if client_list[0]['type'] != 'caSysId':
                # flip the list
                client_list = [client_list[1], client_list[0]]
            if client_list[0]['type'] == 'caSysId' and client_list[1]['type'] == 'macAddr':
                if client_list[0]['value'] == '3584':
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
    match = re.search(r"^video qam-domain (?P<interface>\d+)\n"+
                                        r"(  .*\n)*?"+
                                        r"  qam-group \d+ "+DS, device.config, re.M)
    if match is not None:
        interface = match.group('interface')
    return interface

def get_mac_video(device, DS):
    video = {}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get QAM port
    video['qam_port'] = int(DS.split('/')[1]) + 1
    # get video qam-domain config
    match = re.search(r"^video qam-domain (?P<interface>\d+)\n"+
                      r"(  .*\n)*?"+
                      r"  qam-group \d+ "+DS+r".*", device.config, re.M)
    if match is None:
        return {}
    video_qam_config = match.group(0)
    # get number of channels
    match = re.search(r"^  qam-group \d+ "+DS+r"/(?P<rf_chan_start>\d+) "+DS+r"/(?P<rf_chan_end>\d+)", video_qam_config, re.M)
    if match is None:
        return {}
    start_rf_chan = match.group('rf_chan_start')
    end_rf_chan = match.group('rf_chan_end')
    video['num_channels'] = int(end_rf_chan) - int(start_rf_chan) + 1
    # get video offset
    offset = 0
    match = re.search(r"^video channel-id-offset (?P<offset>\d+)", device.config, re.M)
    if match is not None:
        offset = int(match.group('offset'))
    # calculate starting channel
    video['start_channel'] = int(start_rf_chan) - offset + 1
    # get the QAM config
    match = re.search(r"^interface qam "+DS+r"\n"+
                      r"(  .*\n)+", device.config, re.M)
    if match is None:
        return {}
    qam_config = match.group(0)
    # get the starting TSID
    match = re.search(r"^  channel "+start_rf_chan+r" transport stream id (?P<tsid_start>\d+)", qam_config, re.M)
    if match is None:
        return {}
    video['start_tsid'] = int(match.group('tsid_start'))
    # get video edis
    match = re.search(r"^  edis (?P<edis>\d+)", video_qam_config, re.M)
    if match is None:
        return {}
    video['edis'] = match.group('edis')
    # get interface video
    match = re.search(r"^  interface video (?P<intf>\d+)", video_qam_config, re.M)
    if match is None:
        return {}
    match = re.search(r"^interface video "+match.group('intf')+r"\n"+
                      r"(  .*\n)+", device.config, re.M)
    if match is None:
        return {}
    intf_video_config = match.group(0)
    # get MGMT loopback from interface video
    match = re.search(r"^  edis control-source loopback (?P<loopback>\d+)", intf_video_config, re.M)
    if match is None:
        return {}
    # get MGMT IP
    match = re.search(r"^interface loopback "+match.group('loopback')+r"\n"+
                      r"(  .*\n)*"+
                      r"  ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    if match is None:
        return {}
    video['mgmt_ip'] = match.group('ip')
    # get ingest IP
    match = re.search(r"^  ip address (?P<ip>(\d{1,3}\.){3}\d{1,3})", intf_video_config, re.M)
    if match is None:
        return {}
    video['ingest_ip'] = match.group('ip')
    # get the ingest port
    match = re.search(r"^  input-port-id (?P<ingest_port>\d+)", intf_video_config, re.M)
    if match is None:
        return {}
    video['ingest_port'] = match.group('ingest_port')
    # get the starting frequency
    match = re.search(r"^  channel "+start_rf_chan+r" frequency (?P<start_freq>\d{3})\d+", qam_config, re.M)
    if match is None:
        return {}
    video['start_freq'] = int(match.group('start_freq'))
    # get SG number
    match = re.search(r"^  video service group (?P<num>\d+)", video_qam_config, re.M)
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
                         f'show cable modem {query_value}',
                         f'show cable modem cpe | include {query_value}'
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
    states = ['online', 'init', 'offline']
    states_string = r"("
    for state in states:
        states_string += state+r"|"
    states_string = states_string[:-1]+r")"
    # for each command
    modem.output = ''
    for cmd in cmds:
        cpe_mac = False
        # send the command
        device.get_response(cmd)
        modem.output += '\n'+device.response
        # search the output for the MAC
        match = re.search(r".*\b(?P<cpe_mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})\b.*\b(?P<cm_mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})\b", device.response)
        if match is not None:
            cpe_mac = True
            modem.output = device.response
            cmd = f"show cable modem {match.group('cm_mac')}"
            device.get_response(['', cmd])
        match = re.search(r"^(?P<mac>([\da-fA-F]{4}\.){2}[\da-fA-F]{4})[ ]+(?P<ip>[\da-fA-F:.]+)[ ]+\d{1,2}/\d{1,2}\.\d{1,2}/\d{1,2}(\S+)?[ ]+"+
                          r"\d{1,2}/\d{1,2}/\d{1,2}(\S+)?[ ]+(?P<state>\S*"+states_string+r"\S*)", device.response, re.M|re.I)
        if match is not None:
            modem.mac = match.group('mac')
            modem.state = match.group('state')
            if 'offline' not in modem.state.lower():
                modem.offline = False
            else:
                modem.offline = True
            ip = match.group('ip')
            if ip != '0.0.0.0':
                modem.ipv4 = ip
            # get the IPv6 address (if any)
            match = re.search(r"^[ ]*[\da-fA-F:]+:[\da-fA-F:]+", device.response, re.M)
            if match is not None:
                modem.ipv6 = match.group(0)
            if cpe_mac:
                modem.output += '\n'+device.response
            else:
                modem.output = device.response
            break
#    if match is None:
 #       modem.output = modem.output[1:]
    return modem

