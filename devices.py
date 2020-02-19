#!/usr/bin/python3.6

import re

import parse as p
import ssh

class Device(ssh.Device):
    def __init__(self, data):
        ssh.Device.__init__(self, data)
    def get_info(self):
        get_info(self)
    def get_name(self):
        return get_name(self)
    def no_paging(self):
        cmds = None
        # determine the command
        if self.os in ['IOS', 'IOS-XE', 'IOS-XR', 'NX-OS', 'ADTRAN']:
            cmds = ['terminal length 0', 'terminal width 0']
        elif self.os == 'ARRIS':
            cmds = ['terminal length 0']
        elif self.os == 'CASA':
            cmds = ['page-off']
        elif self.model == 'DAC':
            cmds = ['unset HISTFILE']
        # if commands were found
        if cmds is not None:
            return self.get_response(cmds)
    def save(self):
        cmds = None
        """ get commands and timeout for saving device configurations """
        # determine the command
        if self.os in ['IOS', 'IOS-XE', 'IOS-XR', 'NX-OS', 'ARRIS']:
            cmds = ['write memory']
        elif self.os == 'CASA':
            cmds = ['wr']
        elif self.os == 'ADTRAN':
            cmds = ['copy running-config startup-config', 'y']
        elif self.os == '7360':
            cmds = ['admin save']
        elif self.model == 'GAC':
            cmds = ['commit', 'exit']
        # if commands were found
        if cmds is not None:
            return self.get_response(cmds, timeout=30)
    def get_config(self):
        cmd = None
        self.config = ''
        # determine the command
        if self.os in ['IOS', 'IOS-XE', 'IOS-XR', 'NX-OS', 'CASA', 'ADTRAN', 'ARRIS']:
            cmd = 'show running-config'
        # if a command was found
        if cmd is not None:
            # run the command
            self.config = self.get_response(cmd, timeout=600)
        return self.config
    def get_version(self):
        return get_version(self)
    def snap(self):
        return snapshot(self)

def get_show_version(device):
    device.show_version = ''
    if device.os in ['IOS', 'IOS-XE', 'IOS-XR', 'JUNOS', 'NX-OS', 'ARRIS', 'CASA', 'ADTRAN', 'Arista', 'ACOS', 'GAC']:
        cmd = 'show version'
        device.show_version = device.get_response(cmd, timeout=25)
    elif device.os in ['Linux', 'SunOS']:
        cmd = ['uname -a', 'hostnamectl']
        device.show_version = device.get_response(cmd, timeout=10)
    elif device.os in ['7360']:
        cmd = 'show software-mngt oswp'
        device.show_version = device.get_response(cmd, timeout=10)
    elif device.os in ['Intel']:
        cmd = ['show sys hardware', 'show sys software']
        device.show_version = device.get_response(cmd, timeout=10)

def get_mcounts(device):
    cmd = None
    if device.model in ['E6000', 'C100G', '9504N', '9516']:
        cmd = "show ip mroute"
    elif device.model in ['CBR8']:
        cmd = "show ip mroute count"
    if cmd is not None:
        device.mcounts = device.get_response(cmd)
    else:
        device.mcounts = None

def get_modem_summary(device):
    cmd = None
    if device.model == 'E6000':
        cmd = "show cable modem summary mac"
    elif device.model == 'C100G':
        cmd = "show cable modem summary mac-domain"
    elif device.model in ['CBR8', '9504N', '9516', '7360']:
        cmd = "show cable modem summary"
    elif device.model == 'GAC':
        cmd = "show cable summary | tab | nomore"
    if cmd is not None:
        device.modem_summary = device.get_response(cmd)
    else:
        device.modem_summary = None

def snapshot(device):
    """ returns commands to be used for a snapshot of a device """
    cmds = ""
    if device.model in ['9500', '4500']:
        cmds += """
show users
show version
show vlan brief
show interfaces status
show ip interface brief
show ip route summary
show ipv6 interface brief
show ipv6 route summary
show ip mroute
show ip ospf neighbor
show isis neighbors
show bgp ipv4 unicast summary
show bgp ipv6 unicast summary
show ip arp
show mac address-table
show running-config
"""
    elif device.model == '3850':
        cmds += """
show users
show version
show vlan brief
show interfaces status
show ip interface brief
show ip route summary
show ip arp
show mac address-table
show running-config
"""
    elif device.model == 'E6000':
        cmds += """
show users
show version
show linecard status
show ip interface brief
show ip route summary
show ipv6 interface brief
show ipv6 route summary
show ip mroute
show ip ospf neighbor
show isis neighbor
show bgp ipv4 summary
show bgp ipv6 summary
show ip route rip
show cable modem summary mac
show cable modem
show cable modem detail
show video sessions
show video sessions summary
show running-config verbose
"""
    elif device.model == 'C100G':
        cmds += """
show user current
show version
show chassis status
show ip interface brief
show ip route summary
show ipv6 interface brief
show ip mroute
show ip ospf neighbor
show isis neighbors
show ip bgp summary
show ipv6 bgp summary
show ip route rip
show cable modem docsis-mac summary
show cable modem verbose
show cable modem cpe
show video session all brief
show video session all summary
show running-config
"""
    elif device.model == 'CBR8':
        cmds += """
show users
show version
show platform
show ip interface brief | exclude unset
show ip route summary
show ipv6 interface brief | exclude unass|^Cable|^Video|^In|^Wideband|^Dti|^VirtualPortGroup
show ipv6 route summary
show ip mroute
show ip ospf neighbor
show isis neighbors
show bgp ipv4 unicast summary
show bgp ipv6 unicast summary
show ip route rip
show cable modem summary total
show cable modem verbose
show cable video session all
show cable video session all summary
show running-config
"""
    elif device.model in ['9504N', '9516']:
        cmds += """
show users
show version
show ip interface brief | exclude unass
show ip route summary
show ipv6 interface brief
show ipv6 route summary
show ip mroute
show ip ospf neighbor
show isis neighbors
show bgp ipv4 unicast summary
show bgp ipv6 unicast summary
show ip route rip
show cable modem summary
show cable modem
show running-config
"""
    elif device.model == '7360':
        cmds += """
show session
show software-mngt oswp
show router interface summary
show router ospf neighbor
show router isis interface
show router bgp summary family ipv4
show router bgp summary family ipv6
show router status
show router route-table ipv4 summary
show router route-table ipv6 summary
show cable modem summary total
show cable modem
info configure
"""
    elif device.model == 'GAC':
        cmds += """
show users | nomore
show version | tab | nomore
show router ospf 0 neighbor | nomore
show router isis 0 interface | nomore
show router bgp summary | nomore
show router rip database | nomore
show router route-table ipv4 summary | nomore
show router route-table ipv6 summary | nomore
show cable modem brief | tab | nomore
show cable modem cpe | tab | nomore
show configuration | display set | nomore
"""
    return device.get_response(p.string_to_array(cmds), timeout=300, expect=r"(?m)^(\r)?(\x1b\[(\?7h|K))?(\*)?([)?([\w\-/]+[@:])?[\w\-]+(\[A/U\])?(\([ \w\-]+\))?([ :]~)?(])?(>([\w\-]+)+>)?(>)?([\w\-]+>)*[$#>%]")

############# DETERMINING DEVICE INFO #############
def get_info(device):
    # disable paging
    cmds = ['terminal length 0']
    response = device.get_response(cmds)
    # try 'show version'
    cmd = ['show version', '', '', '', '']
    # get the OS from the output
    response = device.get_response(cmd, timeout=25)
    patterns = [
                [r"(9504N|C9516)", 'ADTRAN' ],
                [r"ACOS",          'ACOS'   ],
                [r"Arista",        'Arista' ],
                [r"Casa",          'CASA'   ],
                [r"Cisco IOS",     'IOS'    ],
                [r"Controller",    'GAC'    ],
                [r"E6000",         'ARRIS'  ],
                [r"IOS[\- ]XE",    'IOS-XE' ],
                [r"IOS[\- ]XR",    'IOS-XR' ],
                [r"JUNOS",         'JUNOS'  ],
                [r"NX-OS",         'NX-OS'  ],
               ]
    for pattern, os in patterns:
        if re.search(r"\b"+pattern+r"\b", response, re.I) is not None:
            device.os = os
            break
    patterns = [
                [r"ASR9K",       'Cisco',    'ASR9K'      ],
                [r"CRS-\d+",     'Cisco',    'CRS-X'      ],
                [r"Nexus7000",   'Cisco',    'Nexus7K'    ],
                [r"Nexus9000",   'Cisco',    'Nexus9K'    ],
                [r"C9500",       'Cisco',    '9500'       ],
                [r"C4500X",      'Cisco',    '4500'       ],
                [r"C3850",       'Cisco',    '3850'       ],
                [r"E6000",       'ARRIS',    'E6000'      ],
                [r"Casa",        'CASA',     'C100G'      ],
                [r"cBR-8",       'Cisco',    'CBR8'       ],
                [r"9504N",       'ADTRAN',   '9504N'      ],
                [r"C9516",       'ADTRAN',   '9516'       ],
                [r"Controller",  'Nokia',    'GAC'        ],
                [r"7750",        'Nokia',    '7750'       ],
                # MISC
                [r"ASR100[012]",  'Cisco',   'ASR1K'      ],
                [r"C2960[SX]?",   'Cisco',   '2960'       ],
                [r"C3650",        'Cisco',   '3650'       ],
                [r"Cisco 3825",   'Cisco',   '3825'       ],
                [r"C4948E",       'Cisco',   '4948'       ],
                [r"NCS-5500",     'Cisco',   '5500'       ],
                [r"CISCO7606",    'Cisco',   '7606'       ],
                [r"Nexus 5596",   'Cisco',   'Nexus5596'  ],
                [r"Nexus5548",    'Cisco',   'Nexus5548'  ],
                [r"Nexus 56128P", 'Cisco',   'Nexus56128' ],
                [r"Nexus 5672UP", 'Cisco',   'Nexus5672UP'],
                [r"Nexus 5696",   'Cisco',   'Nexus5696'  ],
                [r"Nexus 6001",   'Cisco',   'Nexus6K'    ],
                [r"Nexus7700",    'Cisco',   'Nexus7700'  ],
                [r"acx5448",      'Juniper', 'ACX5448'    ],
                [r"qfx10002",     'Juniper', 'QFX10K'     ],
                [r"qfx5100",      'Juniper', 'QFX5K'      ],
                [r"srx3600",      'Juniper', 'SRX3600'    ],
                [r"ex4300",       'Juniper', 'EX4300'     ],
                [r"ptx10008",     'Juniper', 'PTX10008'   ],
                [r"DCS-7150S",    'Arista',  'DCS-7150S'  ],
                [r"DCS-7504N",    'Arista',  'DCS-7504N'  ],
                [r"DCS-7280QR",   'Arista',  'DCS-7280QR' ],
                [r"DCS-7280SR",   'Arista',  'DCS-7280SR' ],
                [r"TH4430",       'Unknown', 'TH4430'     ],
                [r"TH4430S",      'Unknown', 'TH4430S'    ],
                [r"AX2200",       'Unknown', 'AX2200'     ],
                [r"AX2500",       'Unknown', 'AX2500'     ]
               ]
    for pattern, vendor, model in patterns:
        if re.search(r"\b"+pattern+r"\b", response, re.I) is not None:
            device.vendor = vendor
            device.model = model
            return
    # run in-case this is a console server
    cmd = 'shell'
    device.get_response(cmd, timeout=10)
    # try 'uname -a'
    cmds = ['uname -a', '', '']
    response = device.get_response(cmds, timeout=10)
    patterns = [
                [r"Linux", 'Linux'],
                [r"SunOS", 'SunOS']
               ]
    for pattern, model in patterns:
        if re.search(r"\b"+pattern+r"\b", response, re.I) is not None:
            device.os = model
            device.vendor = model
            device.model = model
            return
    # try 'show software-mngt oswp'
    cmd = 'show software-mngt oswp'
    response = device.get_response(cmd, timeout=15)
    patterns = [
                [r"oswp table", 'Nokia', '7360']
               ]
    for pattern, vendor, model in patterns:
        if re.search(r"\b"+pattern+r"\b", response, re.I) is not None:
            device.os = model
            device.vendor = vendor
            device.model = model
            return
    # try 'show sys hardware'
    cmd = 'show sys hardware'
    response = device.get_response(cmd, timeout=10)
    patterns = [
                [r"Intel", 'Intel']
               ]
    for pattern, os in patterns:
        if re.search(r"\b"+pattern+r"\b", response, re.I) is not None:
            device.os = os
            break
    patterns = [
                [r"BIG-IP 5250",            'F5', 'BIG-IP 5250'   ],
                [r"BIG-IP i7800",           'F5', 'BIG-IP i7800'  ],
                [r"BIG-IP Virtual Edition", 'F5', 'BIG-IP Virtual'],
                [r"C109",                   'F5', 'C109'          ]
               ]
    for pattern, vendor, model in patterns:
        if re.search(r"\b"+pattern+r"\b", response, re.I) is not None:
            device.vendor = vendor
            device.model = model
            return

def get_name(device):
    device.found_name = None
    # send a blank line
    cmd = ''
    device.get_response(cmd, timeout=10)
    # search for the name from the command-line
    match = re.search(r"(?m)^(\r)?(\x1b\[(\?7h|K))?(\*)?([)?([\w\-/]+[@:])?(?P<name>[\w\-]+)(\[A/U\])?(\([ \w\->]+\))?([ :](~|[\w\-]+))?(])?(>([\w\-]+)+>)?[$#>%]", device.response)
    if match is None:
        match = re.search(r"(?m)^[\w\-/]+@\((?P<name>[\w\-]+)\)(\([\w\-/ ]+\))+\(tmos\)#", device.response)
    if match is not None:
        device.found_name = match.group('name')
    # if no name was found and this is a Linux or Solaris machine
    if device.found_name is None and device.os in ['Linux', 'SunOS']:
        # in-case this is a console server, enter the shell
        cmd = 'shell'
        device.get_response(cmd, timeout=10)
        # search for the name
        cmd = 'uname -n'
        device.get_response(cmd, timeout=10)
        match = re.search(r"^(Linux )?(?P<name>[\w\-]+)\b", device.response[device.response.find('\n')+1:], re.M)
        if match is not None:
            device.found_name = match.group('name')
    # if name was found and no name was provided
    if device.found_name is not None and device.name is None:
        device.name = device.found_name
    return device.found_name

def get_version(device):
    device.version = None
    # get version output
    if getattr(device, 'show_version', None) is None:
        get_show_version(device)
    if device.os == 'JUNOS':
        match = re.search(r"^Junos:[ ]+(?P<version>[\w\.\-]+)", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
        else:
            match = re.search(r"^JUNOS Software Release \[(?P<version>[\w\.\-]+)\]", device.show_version, re.M)
            if match is not None:
                device.version = match.group('version')
    elif device.os in ['IOS', 'IOS-XE']:
        match = re.search(r", Version (?P<version>[\w\.()]+)(,)? RELEASE SOFTWARE", device.show_version)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'IOS-XR':
        match = re.search(r"Software, Version (?P<version>[\w\.]+)", device.show_version)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'NX-OS':
        # get software section
        match = re.search(r"^Software\n"+
                          r"( .+\n)+", device.show_version, re.M)
        if match is not None:
            match = re.search(r"^[ ]+(NXOS|system):[ ]+version (?P<version>[\w\.()]+)", match.group(0), re.M)
            if match is not None:
                device.version = match.group('version')
    elif device.os == 'Arista':
        match = re.search(r"^Software image version:[ ]+(?P<version>\d+\.\d+\.\w+)", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'ARRIS':
        match = re.search(r"CER_V(?P<version>\d+\.\d+\.\d+\.\d+)", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'ADTRAN':
        match = re.search(r", Version (?P<version>[\w\.]+)", device.show_version)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'CASA':
        match = re.search(r"^Running Image: \S+ Rel (?P<version>[\w\.]+),", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'GAC':
        match = re.search(r"^\S+[ ]+Controller[ ]+(?P<version>[\w.]+)", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    elif device.os == '7360':
        match = re.search(r"^\d+[ ]+(?P<version>[\w\.]+)[ ]+enabled[ ]+active", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'Intel':
        match = re.search(r"^HD\d+\.\d+[ ]+BIG-IP[ ]+(?P<version>[\d\.]+)[ ]+[\d\.]+[ ]+yes", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'ACOS':
        match = re.search(r"version (?P<version>[\w\.\-]+), build", device.show_version)
        if match is not None:
            device.version = match.group('version')
    elif device.os == 'Linux':
        match = re.search(r"^Linux[ ]+\S+[ ]+(?P<version>[\w\.]+)[ ]+", device.show_version, re.M)
        if match is not None:
            device.version = match.group('version')
    return device.version

### Collecting Data ###
import cisco_ios as ios
import cisco_ios_xe as ios_xe
import cisco_ios_xr as ios_xr
import cisco_nx_os as nx_os
import arris
import casa
import adtran

import networking as n

def get_interfaces(device):
    interfaces = [
        {'name': 'PD',     'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None},
        {'name': 'CPU',    'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None},
        {'name': 'Router', 'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None},
        {'name': 'Switch', 'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None}
    ]
    # if device does not have a running-config stored
    if getattr(device, 'config', None) is None:
        # get the running-config
        device.get_config()
    # get interfaces
    if device.os == 'IOS':
        interfaces = ios.get_interfaces(device)
    elif device.os == 'IOS-XE':
        interfaces = ios_xe.get_interfaces(device)
    elif device.os == 'IOS-XR':
        interfaces = ios_xr.get_interfaces(device)
    elif device.os == 'NX-OS':
        interfaces = nx_os.get_interfaces(device)
    elif device.os == 'ARRIS':
        interfaces = arris.get_interfaces(device)
    elif device.os == 'CASA':
        interfaces = casa.get_interfaces(device)
    elif device.os == 'ADTRAN':
        interfaces = adtran.get_interfaces(device)
    # if any interfaces were found
    if len(interfaces) > 0:
        # add interfaces not in running-config (only found in ARP and MAC tables)
        interfaces += [
            {'name': 'PD',     'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None},
            {'name': 'CPU',    'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None},
            {'name': 'Router', 'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None},
            {'name': 'Switch', 'description': None, 'number': '0', 'switchport': None, 'type': 'Manual', 'vlan': None}
        ]
    return interfaces

def get_ips(device):
    ipv4 = []
    ipv6 = []
    # if device does not have a running-config stored
    if getattr(device, 'config', None) is None:
        # get the running-config
        device.get_config()
    # get IPs
    if device.os == 'IOS':
        ipv4, ipv6 = ios.get_ips(device)
    elif device.os == 'IOS-XE':
        ipv4, ipv6 = ios_xe.get_ips(device)
    elif device.os == 'IOS-XR':
        ipv4, ipv6 = ios_xr.get_ips(device)
    elif device.os == 'NX-OS':
        ipv4, ipv6 = nx_os.get_ips(device)
    elif device.os == 'ARRIS':
        ipv4, ipv6 = arris.get_ips(device)
    elif device.os == 'CASA':
        ipv4, ipv6 = casa.get_ips(device)
    elif device.os == 'ADTRAN':
        ipv4, ipv6 = adtran.get_ips(device)
    return ipv4, ipv6

def get_arps(device):
    arps = []
    # get ARPs
    if device.os == 'IOS':
        arps = ios.get_arps(device)
    elif device.os == 'IOS-XE':
        arps = ios_xe.get_arps(device)
    elif device.os == 'IOS-XR':
        arps = ios_xr.get_arps(device)
    elif device.os == 'NX-OS':
        arps = nx_os.get_arps(device)
    elif device.os == 'ARRIS':
        arps = arris.get_arps(device)
    elif device.os == 'CASA':
        arps = casa.get_arps(device)
    elif device.os == 'ADTRAN':
        arps = adtran.get_arps(device)
    # remove redundant entries
    final_arps = []
    for arp in arps:
        missing = True
        for final_arp in final_arps:
            if final_arp['interface'] == arp['interface'] and final_arp['mac'] == arp['mac'] and final_arp['ip'] == arp['ip']:
                missing = False
                break
        if missing:
            final_arps.append(arp)
    return final_arps

def get_macs(device):
    macs = []
    # get MACs
    if device.os == 'IOS':
        macs = ios.get_macs(device)
    elif device.os == 'IOS-XE':
        macs = ios_xe.get_macs(device)
    elif device.os == 'IOS-XR':
        macs = ios_xr.get_macs(device)
    elif device.os == 'NX-OS':
        macs = nx_os.get_macs(device)
    elif device.os == 'ARRIS':
        macs = arris.get_macs(device)
    elif device.os == 'CASA':
        macs = casa.get_macs(device)
    elif device.os == 'ADTRAN':
        macs = adtran.get_macs(device)
    # remove redundant entries
    final_macs = []
    for mac in macs:
        missing = True
        for final_mac in final_macs:
            if final_mac['interface'] == mac['interface'] and final_mac['mac'] == mac['mac']:
                missing = False
                break
        if missing:
            final_macs.append(mac)
    return final_macs

def get_route(device, ip):
    route = None
    # if 'ip' is not an IP class
    if not isinstance(ip, n.IP):
        # create the IP class
        ip = n.IP(ip)
    # if the IP is not valid
    if not ip.valid:
        return None
    # get route
    if device.os == 'IOS':
        route = ios.get_route(device, ip)
    elif device.os == 'IOS-XE':
        route = ios_xe.get_route(device, ip)
    elif device.os == 'IOS-XR':
        route = ios_xr.get_route(device, ip)
    elif device.os == 'NX-OS':
        route = nx_os.get_route(device, ip)
    elif device.os == 'ARRIS':
        route = arris.get_route(device, ip)
    elif device.os == 'CASA':
        route = casa.get_route(device, ip)
    elif device.os == 'ADTRAN':
        route = adtran.get_route(device, ip)
    return route

