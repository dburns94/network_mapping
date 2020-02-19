#!/usr/bin/python3.6
import sys
import re
import json

import networking as n
import devices as d

def get_version(device):
    version = 'Unknown'
    # get the response
    cmd = "show version | tab"
    device.get_response(cmd)
    # parse the response
    match = re.search(r"^\S+[ ]+Controller[ ]+(?P<version>\S+)", device.response, re.M)
    if match is not None:
        version = match.group('version').replace('-pp1','').strip()
    return version

# cmts-status info gathering
def ipConnectivity(device, ips, iphelper):
    pings = []
    # login to the packet-engine
    # create device class for the pakcet-engine
#    device_pe = d.Device('NS1623F0679', '24.28.208.248', model='gainspeed_pe')
    device_pe = d.Device(None, '24.28.208.248', model='gainspeed_pe')
    # if the packet-engine is not pingable
    if not device_pe.up:
        return pings
    # SSH to the packet engine
    device_pe.user = 'admin'
    device_pe.passFile = '/var/www/html/files/pass/gainspeed_pe'
 #   device_pe.expect = device_pe.name+r"#"
    device_pe.connect()
    # if failed to connect
    if device_pe.closed:
        return pings
    # for each IP
    for ip in ips:
        sys.stdout.write('.')
        # send pings
        cmd = f"ping {iphelper} source {ip['address'].split('/')[0]} rapid"
        device_pe.get_response(cmd)
        # get the pings counts
        match = re.search(r"^(?P<sent>\d+)[ ]+packets transmitted, (?P<received>\d+) packets received", device_pe.response, re.M)
        if match is not None:
            pings.append({'ip': ip['address'], 'recieved': match.group('received'), 'transmitted': match.group('sent')})
    # exit the SSH session
    device_pe.close()
    return pings

def channelStatus(device, mac):
    ds_status = []
    us_status = []
    # get cable-macs output
    if getattr(device, 'mac_interface_status', None) is None:
        cmds = [
                "show configuration ccap chassis | display set | match rf-line-card | match rf-port | match channel | nomore",
                "show configuration ccap docsis docs-mac-domain mac-domain | display set | nomore"
               ]
        device.mac_interface_status = device.get_response(cmds)
    # get the slot and port
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)/\d+", mac)
    if match is None:
        return ds_status, us_status
    slot = match.group('slot')
    port = match.group('port')
    # get the DS channels
    channels = []
    #matches = re.finditer(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" down-channel (?P<channel>\d+) docsis-down-channel id \d+", device.mac_interface_status, re.M)
    matches = re.finditer(r"^set ccap docsis docs-mac-domain mac-domain "+mac+r" primary-capable-ds "+slot+r" "+port+r" (?P<channel>\d+)", device.mac_interface_status, re.M)
    for match in matches:
        if match.group('channel') not in channels:
            channels.append(match.group('channel'))
    # for each DS channel
    for channel in channels:
        # get the admin-state
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" down-channel "+channel+r" admin-state (?P<status>\S+)", device.mac_interface_status, re.M)
        if match is None:
            continue
        status = match.group('status')
        # get the frequency
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" down-channel "+channel+r" frequency (?P<freq>\d+)0{6}\b", device.mac_interface_status, re.M)
        if match is None:
            continue
        sys.stdout.write('.')
        ds_status.append({'channel': channel, 'status': status, 'frequency': match.group('freq'), 'power': '-'})
    # get the US channels
    channels = []
    #matches = re.finditer(r"^set ccap chassis slot "+slot+r" rf-line-card us-rf-port "+port+r" upstream-physical-channel (?P<channel>\d+)", device.mac_interface_status, re.M)
    matches = re.finditer(r"^set ccap docsis docs-mac-domain mac-domain "+mac+r" upstream-physical-channel-ref "+slot+r" "+port+r" (?P<channel>\d+)", device.mac_interface_status, re.M)
    for match in matches:
        if match.group('channel') not in channels:
            channels.append(match.group('channel'))
    # for each US channel
    for channel in channels:
        # get the admin-state
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card us-rf-port "+port+r" upstream-physical-channel "+channel+r" admin-state (?P<status>\S+)", device.mac_interface_status, re.M)
        if match is None:
            continue
        status = match.group('status')
        # get the frequency
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card us-rf-port "+port+r" upstream-physical-channel "+channel+r" frequency (?P<freq>\d+)0{5}\b", device.mac_interface_status, re.M)
        if match is None:
            continue
        center_freq = float(match.group('freq'))/10
        # get the width
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card us-rf-port "+port+r" upstream-physical-channel "+channel+r" width (?P<width>\d+)0{5}\b", device.mac_interface_status, re.M)
        if match is None:
            continue
        width = float(match.group('width'))/10
        bottom = round(center_freq-width/2,1)
        top = round(center_freq+width/2,1)
        sys.stdout.write('.')
        us_status.append({'channel': channel, 'status': status, 'frequency': f"{bottom}-{top}", 'power': '-'})
    # get the OFDM channels
    channels = []
    matches = re.finditer(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" ofdm-channel (?P<channel>\d+)", device.mac_interface_status, re.M)
    for match in matches:
        if match.group('channel') not in channels:
            channels.append(match.group('channel'))
    # for each OFDM channel
    for channel in channels:
        # get the admin-state
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" ofdm-channel "+channel+r" admin-state (?P<status>\S+)", device.mac_interface_status, re.M)
        if match is None:
            continue
        status = match.group('status')
        # get the frequency
        match = re.search(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" ofdm-channel "+channel+r" plc-blk-freq (?P<freq>\d+)0{6}\b", device.mac_interface_status, re.M)
        if match is None:
            continue
        sys.stdout.write('.')
        ds_status.append({'channel': channel, 'status': status, 'frequency': match.group('freq'), 'power': '-'})
    return ds_status, us_status

def getMCounts(device, mac, multicasts):
    counts = []
    # get the slot
    match = re.search(r"(?P<slot>\d+)/\d+/\d+", mac)
    if match is None:
        return counts
    slot = match.group('slot')
    # get multicast counts
    if getattr(device, 'mcounts', None) is None:
        device.mcounts = {}
    if device.mcounts.get(slot) is None:
        device.mcounts[slot] = {}
        # get the resonse
        cmd = f"show network {slot} downstream-classifier action mcast | tab | nomore"
        device.mcounts[slot] = device.get_response(cmd, timeout=30)
    # get all counts from the response
    all_counts = []
    matches = re.finditer(r"^\d+[ ]+\d+[ ]+\d+[ ]+(?P<matches>\d+)[ ]+mcast[ ]+pass[ ]+\S+[ ]+\d+([ ]+\S+[ ]+\S+[ ]*\n)*"+
                          r"[ ]+ip4\.dest[ ]+(?P<group>(\d{1,3}\.){3}\d{1,3})\b", device.mcounts[slot], re.M)
    for match in matches:
        all_counts.append({'matches': match.group('matches'), 'group': match.group('group')})
    # for each multicast
    for mcast in multicasts:
        sys.stdout.write('.')
        # for each count found
        for count in all_counts:
            if mcast['multicast'] == count['group']:
                # get the packet count
                counts.append({'multicast': {'multicast': mcast['multicast'], 'source': mcast['source']}, 'count': int(count['matches']),
                               'type': mcast['type'], 'tunnel': mcast['tunnel']})
    return counts

def getDSGcounts(device, DS, tunnels):
    counts = []
    # get DSG counts
#    if getattr(device, 'dsg_counts', None) is None:
 #       cmd = "show cable dsg counts"
  #      device.dsg_counts = device.get_response(cmd)
    return counts

def getSNR(device, mac):
    snr_readings = []
    # get the slot and port
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)/\d+", mac)
    if match is None:
        return snr_readings
    slot = match.group('slot')
    port = match.group('port')
    # get noise readings
    if getattr(device, 'snr', None) is None:
        device.snr = {}
    if device.snr.get(slot) is None:
        cmd = f"show ccap chassis slot {slot} rf-line-card us-rf-port upstream-physical-channel counter snr | tab | nomore"
        device.snr[slot] = device.get_response(cmd, timeout=20)
    # get channel SNR section
    match = re.search(r"^"+port+r"(?P<snr_readings>([ ]+\d+[ ]+(-)?\d+\.\d+[ ]*\n)+)", device.snr[slot], re.M)
    if match is None:
        return snr_readings
    # get each channels SNR
    matches = re.finditer(r"^[ ]+(?P<channel>\d+)[ ]+(?P<snr>(-)?\d+\.\d+)", match.group('snr_readings'), re.M)
    for match in matches:
        sys.stdout.write('.')
        # convert SNR to a float
        snr = float(match.group('snr'))
        # only keep non-zero SNR readings
        if snr != 0:
            snr_readings.append({'channel': match.group('channel'), 'snr': snr})
    return snr_readings

def cmCount(device, mac):
    counts = {'online': 0, 'total': 0}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the slot, port, and index number
    number = None
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)/(?P<index>\d+)", mac)
    if match is not None:
        number = match.group('slot')+r"[ ]+"+match.group('port')+r"[ ]+"+match.group('index')
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^"+number+r"[ ]+(?P<total_devices>\d+)[ ]+(?P<total>\d+)[ ]+\d+[ ]+\d+[ ]+\d+[ ]+(?P<offline>\d+)[ ]+(?P<ranging>\d+)[ ]+(?P<online>\d+)", device.modem_summary, re.M)
        if match is not None:
            counts['total'] = int(match.group('total'))
            counts['online'] = int(match.group('online'))
    return counts

############################################################
############### Networking #################################
############################################################
def get_ips(device, link_local=True):
    ipv4 = []
    ipv6 = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get GAC loopback
    matches = re.finditer(r"^set ccap interface controller-loopback unit \d+ family inet[46] address (?P<ip>([\da-fA-F:]+/\d{1,3}|(\d{1,3}\.){3}\d{1,3}/\d{1,2}))", device.config, re.M)
    for match in matches:
        # get the IP address
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            interface = 'loopback GAC'
            # if this is an IPv4 address
            if ip.type == 4:
                # add IPv4 data to address list
                #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
                ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
            else:
                # calculate the first three half-hextets
                first_hex, sec_hex, third_hex = ip.first_three
                # add IPv6 data to address list
                #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
                ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    # get the PE interfaces (packet-engine)
    interfaces = []
    matches = re.finditer(r"^set ccap chassis slot \d+ sre-line-card configure router Base interface (?P<interface>\S+)", device.config, re.M)
    for match in matches:
        if match.group('interface') not in interfaces:
            interfaces.append(match.group('interface'))
    # for each PE interface
    for interface in interfaces:
        # get the IPv4 address
        match = re.search(r"^set ccap chassis slot \d+ sre-line-card configure router Base interface "+interface+r" address ip-address-mask "+
                          r"(?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", device.config, re.M)
        if match is not None:
            # get the IP address
            ip = n.IP(match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # add IPv4 data to address list
                #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
                ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
        # get the IPv6 address
        match = re.search(r"^set ccap chassis slot \d+ sre-line-card configure router Base interface "+interface+r" ipv6 address (?P<ip>[\da-fA-F:]+/\d{1,3})", device.config, re.M)
        if match is not None:
            # get the IP address
            ip = n.IP(match.group('ip'))
            # if this is a valid IP address
            if ip.valid:
                # calculate the first three half-hextets
                first_hex, sec_hex, third_hex = ip.first_three
                # add IPv6 data to address list
                #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
                ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
    # get the Bundle IPv4 addresses
    matches = re.finditer(r"^set ccap interface (?P<interface>cable-bundle \d+) ip-interface \S+ (primary|secondary)-ipv4 (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", device.config, re.M)
    for match in matches:
        # get the IP address
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # get the interface
            interface = match.group('interface')
            # add IPv4 data to address list
            #ipv4.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first': ip.nth(0, dec=True), 'last': ip.nth('last', dec=True)})
            ipv4.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First': ip.nth(0, dec=True), 'Last': ip.nth('last', dec=True)})
    # get the Bundle IPv6 addresses
    matches = re.finditer(r"^set ccap interface (?P<interface>cable-bundle \d+) ip-interface \S+ ipv6 (?P<ip>[\da-fA-F:]+/\d{1,3})", device.config, re.M)
    for match in matches:
        # get the IP address
        ip = n.IP(match.group('ip'))
        # if this is a valid IP address
        if ip.valid:
            # get the interface
            interface = match.group('interface')
            # calculate the first three half-hextets
            first_hex, sec_hex, third_hex = ip.first_three
            # add IPv6 data to address list
            #ipv6.append({'interface': interface, 'network': ip.network, 'ip': ip.addr, 'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex, 'link_local': None})
            ipv6.append({'Interface': interface, 'Network': ip.network, 'Assigned': ip.addr, 'First Hex': first_hex, 'Sec Hex': sec_hex, 'Link-Local': None})
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
    matches = re.finditer(r"^\d+[ ]+\d+[ ]+\d+[ ]+\d+[ ]+(?P<total>\d+)[ ]+\d+[ ]+\d+[ ]+\d+[ ]+(?P<offline>\d+)[ ]+\d+[ ]+(?P<online>\d+)[ ]+(?P<registered>\d+)", device.response, re.M)
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
    matches = re.finditer(r"^set ccap docsis docs-mac-domain mac-domain (?P<mac>\d+/\d+/\d+)", device.config, re.M)
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
    match = re.search(r"^set ccap docsis docs-mac-domain mac-domain "+mac+r" description (?P<description>[\S ]+)", device.config, re.M)
    if match is not None:
        description = match.group('description')
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    # get the slot and port
    match = re.search(r"(?P<ds_us>(?P<slot>\d+)/(?P<port>\d+))/\d+", mac)
    if match is not None:
        DS = match.group('ds_us')
        US = match.group('ds_us')
    return DS, US

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get the slot and port
    slot = None
    port = None
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)/\d+", mac)
    if match is not None:
        slot = match.group('slot')
        port = match.group('port')
    if slot is not None and port is not None:
        # count DS channels
        #matches = re.finditer(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" down-channel \d+ docsis-down-channel id \d+", device.config, re.M)
        matches = re.finditer(r"^set ccap docsis docs-mac-domain mac-domain "+mac+r" primary-capable-ds "+slot+r" "+port+r" \d+", device.config, re.M)
        for match in matches:
            counts['DS'] += 1
        # count US channels
        #matches = re.finditer(r"^set ccap chassis slot "+slot+r" rf-line-card us-rf-port "+port+r" upstream-physical-channel \d+ admin-state up", device.config, re.M)
        matches = re.finditer(r"^set ccap docsis docs-mac-domain mac-domain "+mac+r" upstream-physical-channel-ref "+slot+r" "+port+r" \d+", device.config, re.M)
        for match in matches:
            counts['US'] += 1
        # count OFDM channels
        matches = re.finditer(r"^set ccap chassis slot "+slot+r" rf-line-card ds-rf-port "+port+r" ofdm-channel \d+ admin-state up", device.config, re.M)
        for match in matches:
            counts['OFDM'] += 1
    return counts

def get_mac_cm_counts(device, mac):
    counts = {'online': 0, 'total': 0, 'percent': 100}
    # get cable modem summary
    if getattr(device, 'modem_summary', None) is None:
        device.get_modem_summary()
    # get the slot, port, and index number
    number = None
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)/(?P<index>\d+)", mac)
    if match is not None:
        number = match.group('slot')+r"[ ]+"+match.group('port')+r"[ ]+"+match.group('index')
    # if the cable-mac number was found
    if number is not None:
        # get the modem counts
        match = re.search(r"^"+number+r"[ ]+(?P<total_devices>\d+)[ ]+(?P<total>\d+)[ ]+\d+[ ]+\d+[ ]+\d+[ ]+(?P<offline>\d+)[ ]+(?P<ranging>\d+)[ ]+(?P<online>\d+)", device.modem_summary, re.M)
        if match is not None:
            counts['total'] = int(match.group('total'))
            counts['online'] = int(match.group('online'))
            if counts['total'] > 0:
                counts['percent'] = round((counts['online']/counts['total'])*100, 1)
    return counts

def get_mac_IP_interface(device, mac):
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # check if this is a slave bundle
    match = re.search(r"^set ccap interface (?P<interface>cable-bundle \d+) docsis-mac-domain "+mac, device.config, re.M)
    if match is not None:
        interface = match.group('interface')
    return interface

def get_mac_IPs(device, interface):
    ipv4 = []
    ipv6 = []
    ipv4helper = []
    ipv6helper = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get IPv4 addresses
    matches = re.finditer(r"^set ccap interface "+interface+" ip-interface \w+ (primary|secondary)-ipv4 (?P<ip>(\d{1,3}\.){3}\d{1,3}/\d{1,2})", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid:
            ipv4.append({'interface': interface, 'address': str(ip)})
    # get IPv4 helpers
    matches = re.finditer(r"^set ccap interface "+interface+" cable-helper-config \d+ ip-address (?P<ip>(\d{1,3}\.){3}\d{1,3})", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid and ip.addr not in ipv4helper:
            ipv4helper.append(ip.addr)
    # get IPv6 addresses
    matches = re.finditer(r"^set ccap interface "+interface+" ip-interface \w+ ipv6 (?P<ip>[\da-fA-F:]+/\d{1,3})", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid:
            ipv6.append({'interface': interface, 'address': str(ip)})
    # get IPv6 helpers
    matches = re.finditer(r"^set ccap interface "+interface+" cable-helper-config \d+ ip-address (?P<ip>[\da-fA-F:]+)", device.config, re.M)
    for match in matches:
        ip = n.IP(match.group('ip'))
        if ip.valid and ip.addr not in ipv6helper:
            ipv6helper.append(ip.addr)
    return ipv4, ipv4helper, ipv6, ipv6helper

def get_mac_video_interface(device, DS):
    interface = None
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get slot and port
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)", DS)
    if match is not None:
        # get video interface
        match = re.search(r"^set ccap video video-service-group (?P<interface>\S+) en-port-list "+match.group('slot')+r" "+match.group('port'), device.config, re.M)
        if match is not None:
            interface = match.group('interface')
    return interface

def get_mac_DSG_tunnels(device, DS):
    tunnels = []
    # get running-config
    if getattr(device, 'config', None) is None:
        device.get_config()
    # get the slot and port
    match = re.search(r"(?P<slot>\d+)/(?P<port>\d+)", DS)
    if match is not None:
        slot = match.group('slot')
        port = match.group('port')
    else:
        return []
    # get all DSG downstreams
    dsg_downstreams = []
    matches = re.finditer(r"^set ccap docsis docs-dsg dsg-downstream (?P<ds>\d+) docsis-down-channel-ref slot "+slot+r"\b.*\n"+
                          r"set ccap docsis docs-dsg dsg-downstream (?P=ds) docsis-down-channel-ref ds-rf-port "+port+r"\b", device.config, re.M)
    for match in matches:
        if match.group('ds') not in dsg_downstreams:
            dsg_downstreams.append(match.group('ds'))

    # get all DSG tunnel-groups
    tgs = []
    for dsg_ds in dsg_downstreams:
        matches = re.finditer(r"^set ccap docsis docs-dsg tunnel-group-to-channel-list (?P<tg>\d+) tunnel-group-channel \d+ dsg-downstream-index "+dsg_ds+r"\b", device.config, re.M)
        for match in matches:
            if match.group('tg') not in tgs:
                tgs.append(match.group('tg'))
    # get all tunnels numbers
    tunnel_indices = []
    for tg in tgs:
        matches = re.finditer(r"^set ccap docsis docs-dsg dsg-tunnel-config (?P<tunnel>\d+) tunnel-grp-index "+tg+r"\b", device.config, re.M)
        for match in matches:
            if match.group('tunnel') not in tunnel_indices:
                tunnel_indices.append(match.group('tunnel'))

    # get all tunnels
    for tunnel_index in tunnel_indices:
        # get tunnel config
        match = re.search(r"^(set ccap docsis docs-dsg dsg-tunnel-config "+tunnel_index+r" .*\n)+", device.config, re.M)
        if match is None:
            continue
        tunnel_config = match.group(0)
        # get the DSG tunnel-group
        match = re.search(r"^set ccap docsis docs-dsg dsg-tunnel-config "+tunnel_index+r" tunnel-grp-index (?P<tg>\d+)", tunnel_config, re.M)
        if match is None:
            continue
        tg = match.group('tg')
        # get the MAC address
        match = re.search(r"^set ccap docsis docs-dsg dsg-tunnel-config "+tunnel_index+r" mac-address (?P<mac>([\da-fA-F]{2}:){5}[\da-fA-F]{2})", tunnel_config, re.M)
        if match is None:
            continue
        mac = match.group('mac')
        # get the client-list
        match = re.search(r"^set ccap docsis docs-dsg dsg-tunnel-config "+tunnel_index+r" client-id-list-index (?P<client_list>\d+)", tunnel_config, re.M)
        if match is None:
            continue
        client_list = match.group('client_list')
        # get the tunnel classifier config
        match = re.search(r"^set ccap docsis docs-dsg dsg-classifier (?P<classifier>\d+) tunnel-index "+tunnel_index+r"\b.*\n"+
                          r"(set ccap docsis docs-dsg dsg-classifier (?P=classifier) .+\n)*", device.config, re.M)
        if match is None:
            continue
        tunnel_config = match.group(0)
        classifier = match.group('classifier')
        # get the source IP
        match = re.search(r"^set ccap docsis docs-dsg dsg-classifier "+classifier+r" source-ip (?P<source>(\d{1,3}\.){3}\d{1,3})/\d{1,2}", tunnel_config, re.M)
        if match is None:
            continue
        source = match.group('source')
        # get the multicast
        match = re.search(r"^set ccap docsis docs-dsg dsg-classifier "+classifier+r" destination-ip (?P<destination>(\d{1,3}\.){3}\d{1,3})", tunnel_config, re.M)
        if match is None:
            continue
        dest = match.group('destination')
        # collect tunnel data
        tunnels.append({'index': tunnel_index, 'group': tg, 'client-list': {'id': client_list, 'data':[]}, 'mac': mac, 'classifier': classifier,
                        'source': source, 'multicast': dest})
    # for each tunnel found
    for i in range(len(tunnels)):
        # collect client-list data
        indices = []
        matches = re.finditer(r"^set ccap docsis docs-dsg client-id-config-list "+tunnels[i]['client-list']['id']+r" dsg-client (?P<index>\d+) .*\n", device.config, re.M)
        for match in matches:
            if match.group('index') not in indices:
                indices.append(match.group('index'))
        for index in indices:
            match = re.search(r"^(set ccap docsis docs-dsg client-id-config-list "+tunnels[i]['client-list']['id']+r" dsg-client "+index+r" .*\n)+", device.config, re.M)
            if match is None:
                continue
            client_list_config = match.group(0)
            # get the client-list index type
            match = re.search(r"dsg-client-id-type (?P<type>\S+)", client_list_config)
            if match is None:
                continue
            index_type = match.group('type')
            # get the client-list index value
            match = re.search(r"client-id-value (?P<value>[\da-fA-F]+)", client_list_config)
            if match is None:
                continue
            index_value = match.group('value')
            # add client-list data to the tunnel
            tunnels[i]['client-list']['data'].append({'index': index, 'type': index_type, 'value': index_value})
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
                if client_list[0]['value'] == '000000000001':
                    tunnel_type = 'Cisco Global'
                elif client_list[0]['value'] == '000000000002':
                    tunnel_type = 'EAS'
                elif client_list[0]['value'] == '000000000005':
                    tunnel_type = 'DCAS CVT'
                elif client_list[0]['value'] == '00000000d903':
                    tunnel_type = 'DCAS SI'
                elif client_list[0]['value'] == '00000000d904':
                    tunnel_type = 'DCAS CVT 2'
            elif client_list[0]['type'] == 'ca-system-id':
                if client_list[0]['value'] == '000000000700':
                    tunnel_type = 'ARRIS CA'
                elif client_list[0]['value'] == '000000000700':
                    tunnel_type = 'ARRIS DSP'
                elif client_list[0]['value'] == '0x96b':
                    tunnel_type = 'DCAS CA'
                elif client_list[0]['value'] == '000000000e00':
                    tunnel_type = 'Cisco Hub'
            elif client_list[0]['type'] == 'application-id':
                if client_list[0]['value'] == '000000000001':
                    tunnel_type = 'ARRIS EPG'
                elif client_list[0]['value'] == '000000000002':
                    tunnel_type = 'ODN TSB'
                elif client_list[0]['value'] == '000000000005':
                    tunnel_type = 'ADB XAIT'
                elif client_list[0]['value'] == '000000000006':
                    tunnel_type = 'ARRIS SDV'
                elif client_list[0]['value'] == '0000000007D0':
                    tunnel_type = 'DCAS EPG'
        elif len(client_list) == 2:
            # if 'ca-system-id' is not first
            if client_list[0]['type'] != 'ca-system-id':
                # flip the list
                client_list = [client_list[1], client_list[0]]
            if client_list[0]['type'] == 'ca-system-id' and client_list[1]['type'] == 'mac-address':
                if client_list[0]['value'] == '000000000e00':
                    if client_list[1]['value'].startswith('0001a6fe'):
                        tunnel_type = 'Cisco System'
                    elif client_list[1]['value'].startswith('0001a6ff'):
                        tunnel_type = 'Cisco Hub or CMTS Bridge'
    return tunnel_type

############################################################
############### CM #########################################
############################################################
def get_modem(device, modem, query_value, query_type):
    # declare command set
    cmd_sets = {
                'MAC':  [
                         f"show cable modem {n.formatMAC(query_value, char=':')} brief | tab",
                         f"show cable modem cpe | tab | match {n.formatMAC(query_value, char=':')}"
                        ],
                'IPv4': [
                         f'show cable modem brief | tab | match {query_value}',
                         f'show cable modem cpe {query_value} | tab'
                        ],
                'IPv6': [
                         f'show cable modem brief | tab | match {query_value}',
                         f'show cable modem cpe {query_value} | tab'
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
            cmd = f"show cable modem {n.formatMAC(match.group('cm_mac'), char=':')} brief"
            device.get_response(['', cmd])
        match = re.search(r"^(\d+[ ]+\d+[ ]+\d+)?[ ]+(?P<mac>([\da-fA-F]{2}:){5}[\da-fA-F]{2})[ ]+"+
                          r"(?P<ip>((\d{1,3}\.){3}\d{1,3})|[\da-fA-F:]+)[ ]+(?P<state>\S+)", device.response, re.M)
        if match is not None:
            modem.output = device.response
            modem.mac = n.formatMAC(match.group('mac'), char='.')
            modem.state = match.group('state')
            if 'offline' not in modem.state.lower():
                modem.offline = False
            else:
                modem.offline = True
            ip = n.IP(match.group('ip'))
            if ip.type == 4 and ip.addr != '0.0.0.0':
                modem.ipv4 = ip
            elif ip.type == 6:
                modem.ipv6 = ip
            break
#    if match is None:
 #       modem.output = modem.output[1:]
    return modem

