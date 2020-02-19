#!/usr/bin/python3.6

import re

import networking as n

def verify_keys_exist(data, keys):
    """ verifies a key, value pair has all given keys """
    has_all_keys = True
    if type(keys) is str:
        keys = [keys]
    for key in keys:
        if data.get(key) is None:
            has_all_keys = False
            break
    return has_all_keys

def get_all_servers():
    validated_servers = {}
    # initial servers
    servers = {
               'L-TWC Herndon IPv4':    {
                                         'primary': {
                                                     'name': 'dhc01ppd',
                                                     'ip': '107.14.109.77'
                                                    },
                                         'user': 'ipmgmt',
                                         4: True,
                                         6: False
                                        },
               'L-TWC Herndon IPv6':    {
                                         'primary': {
                                                     'name': 'h2t',
                                                     'ip': '107.14.109.78'
                                                    },
                                         'user': 'ipmgmt',
                                         4: False,
                                         6: True
                                        },
               'L-BHN IPv4':            {
                                         'primary': {
                                                     'name': 'dhc05ppd',
                                                     'ip': '107.14.109.121'
                                                    },
                                         'user': 'ipmgmt',
                                         4: True,
                                         6: False
                                        },
               'L-BHN IPv6':            {
                                         'primary': {
                                                     'name': 'dhc07ppd',
                                                     'ip': '107.14.109.122'
                                                    },
                                         'user': 'ipmgmt',
                                         4: False,
                                         6: True
                                        },
               'L-TWC Broomfield IPv4': {
                                         'primary': {
                                                     'name': 'h9t',
                                                     'ip': '107.14.108.174'
                                                    },
                                         'user': 'ipmgmt',
                                         4: True,
                                         6: False
                                        },
               'L-TWC Broomfield IPv6': {
                                         'primary': {
                                                     'name': 'h10t',
                                                     'ip': '107.14.108.175'
                                                    },
                                         'user': 'ipmgmt',
                                         4: False,
                                         6: True
                                        },
               'L-CHTR SA':             {
                                         'primary': {
                                                     'name': 'kbsacc',
                                                     'ip': '96.37.171.164'
                                                    },
#                                         'backup': {
 #                                                    'name': 'kbsacc?',
  #                                                   'ip': '96.37.171.165'
   #                                                 },
                                         'user': 'dburns',
                                         4: True,
                                         6: True
                                        }
#               'L-TWC SA IPv4':         {
 #                                        'primary': {
  #                                                   'name': 'dhc03int',
   #                                                  'ip': '172.16.18.51'
    #                                                },
     #                                    'user': 'ipmgmt'
      #                                  },
       #        'L-TWC SA IPv6':         {
        #                                 'primary': {
         #                                            'name': 'dhc05int',
          #                                           'ip': '172.16.18.52'
           #                                         },
            #                             'user': 'ipmgmt'
             #                           }
#               'L-CHTR SC IPv4':        {
 #                                        'primary': {
  #                                                   'name': 'dhc04int',
   #                                                  'ip': '22.254.33.84'
    #                                                },
     #                                    'user': 'ipmgmt'
      #                                  },
       #        'L-CHTR SC IPv6':        {
        #                                 'primary': {
         #                                            'name': 'dhc06int',
          #                                           'ip': '22.254.33.86'
           #                                         },
            #                             'user': 'ipmgmt'
             #                           }
                  }
    # for each server
    for server, server_data in servers.items():
        # if any required data is missing
        if not verify_keys_exist(server_data['primary'], ['name', 'ip']) or not verify_keys_exist(server_data, 'user'):
            # skip
            continue
        # if required data is not missing
        validated_servers[server] = server_data
    return validated_servers

def read_passFile(passFile):
    """ returns the password inside a passFile """
    try:
        with open(passFile, 'r') as inFile:
            passwd = inFile.read()
    except:
        return ''
    return passwd[:-1]

def open_nrcmd(device, server_data):
    # login to nrcmd
    cmds = ['/opt/nwreg2/usrbin/nrcmd', server_data['user'], read_passFile(device.passFile)]
    device.get_response(cmds)

def close_nrcmd(device):
    # exit nrcmd
    cmd = 'exit'
    device.get_response(cmd)

def parse_default(string):
    """ returns the value from a property """
    match = re.search(r"\[default=(?P<value>\S+)\]", string)
    if match is not None:
        return match.group('value')
    return string

def get_backup_servers(device):
    servers = []
    # send command to list all backup servers
    cmd = 'failover-pair listnames'
    device.get_response(cmd)
    # parse the response
    matches = re.finditer(r"^(?P<server>\S+)\n", device.response, re.M)
    # for each match
    for match in matches:
        servers.append(match.group('server'))
    return servers

def get_templates(device):
    templatesv4 = []
    templatesv6 = []
    # declare patterns
    policy_pattern = re.compile(r"^    policy = (?P<policy>\S+)", re.M)
    range_pattern = re.compile(r"^    ranges-expr = \"\(create-range (?P<range>.*)\)\"", re.M)
    tags_pattern = re.compile(r"^    selection-tag(-list|s) = \{(\{\d+ \S+\}[ ]?)+\}", re.M)
    tag_pattern = re.compile(r"\{\d+ (?P<tag>\S+?)\}")
    dhcp_pattern = re.compile(r"^    dhcp-type = (?P<dhcp_type>\S+)", re.M)
    # send command to get the IPv4 templates
    cmd = 'scope-template list'
    device.get_response(cmd)
    # parse the response
    matches = re.finditer(r"^(?P<name>\S+):\n"+
                          r"(    .+\n)+", device.response, re.M)
    # for each match
    for match in matches:
        # initialize the variable
        template = {'name': match.group('name'), 'policy': None, 'range_expr': None, 'tags': []}
        # get the policy
        policy_match = policy_pattern.search(match.group(0))
        if policy_match is not None:
            template['policy'] = policy_match.group('policy')
        # get the range expression
        range_match = range_pattern.search(match.group(0))
        if range_match is not None:
            template['range_expr'] = range_match.group('range')
        # get the tags string
        tags_match = tags_pattern.search(match.group(0))
        if tags_match is not None:
            # get each tag
            tag_matches = tag_pattern.finditer(tags_match.group(0))
            for tag_match in tag_matches:
                template['tags'].append(tag_match.group('tag'))
        templatesv4.append(template)
    # send command to get the IPv6 templates
    cmd = 'prefix-template list'
    device.get_response(cmd)
    # parse the response
    matches = re.finditer(r"^(?P<name>\S+):\n"+
                          r"(    .+\n)+", device.response, re.M)
    # for each match
    for match in matches:
        # initialize the variable
        template = {'name': match.group('name'), 'policy': None, 'type': None, 'tags': []}
        # get the policy
        policy_match = policy_pattern.search(match.group(0))
        if policy_match is not None:
            template['policy'] = policy_match.group('policy')
        # get the DHCP type
        dhcp_match = dhcp_pattern.search(match.group(0))
        if dhcp_match is not None:
            template['type'] = parse_default(dhcp_match.group('dhcp_type'))
        # get the tags string
        tags_match = tags_pattern.search(match.group(0))
        if tags_match is not None:
            # get each tag
            tag_matches = tag_pattern.finditer(tags_match.group(0))
            for tag_match in tag_matches:
                template['tags'].append(tag_match.group('tag'))
        templatesv6.append(template)
    return templatesv4, templatesv6

def get_policies(device):
    policies = []
    # delcare options to keep
    keep_options = ['dhcp_lease_time', 'domain_name', 'domain_name_servers', 'ntp_servers', 'dns_servers', 'dhcp_rebinding_time', 'dhcp_renewal_time', 'domain_list']
    # declare options that are a list
    list_options = ['domain_name_servers', 'dns_servers']
    # send command to get all policies
    cmd = 'policy list'
    device.get_response(cmd)
    # parse the response
    matches = re.finditer(r"^(?P<name>\S+):\n"+
                          r"(?P<data>([ ]+.*\n)+)", device.response, re.M)
    # for each match
    for match in matches:
        # get the name
        name = match.group('name')
        # collect the data
        data = match.group('data')
        # get the offer-timeout
        match = re.search(r"^[ ]+offer-timeout = (?P<timeout>\w+)", data, re.M)
        if match is None:
            continue
        offer_timeout = parse_default(match.group('timeout'))
        # get the preferred-lifetime
        match = re.search(r"^[ ]+preferred-lifetime = (?P<lifetime>\S+)", data, re.M)
        if match is None:
            continue
        preferred_lifetime = parse_default(match.group('lifetime'))
        # get the valid-lifetime
        match = re.search(r"^[ ]+valid-lifetime = (?P<lifetime>\S+)", data, re.M)
        if match is None:
            continue
        valid_lifetime = parse_default(match.group('lifetime'))
        # add info to the final list
        policy = {
                  'name': name, 'offer_timeout': offer_timeout, 'preferred_lifetime': preferred_lifetime, 'valid_lifetime': valid_lifetime,
                  'dhcp_lease_time': None, 'domain_name': None, 'domain_name_servers': None, 'ntp_servers': None,
                  'dns_servers': None
                 }
        # send command to get the IPv4 options
        cmd = f"policy {name} listOptions"
        device.get_response(cmd)
        #print(device.response)
        # get all options
        option_matches = re.finditer(r"^\d+[ ]+(?P<option>\S+)[ ]+\S+:[ ]+(?P<value>\S+)", device.response, re.M)
        for option_match in option_matches:
            option = option_match.group('option').replace('-','_')
            if option in keep_options:
                value = option_match.group('value')
                if option in list_options:
                    policy[option] = value.split(',')
                else:
                    policy[option] = value
        # send command to get the IPv6 options
        cmd = f"policy {name} listv6Options"
        device.get_response(cmd)
        #print(device.response)
        # get all options
        option_matches = re.finditer(r"^\d+[ ]+(?P<option>\S+)[ ]+\S+:[ ]+(?P<value>\S+)", device.response, re.M)
        for option_match in option_matches:
            option = option_match.group('option').replace('-','_')
            if option in keep_options:
                value = option_match.group('value')
                if option in list_options:
                    policy[option] = value.split(',')
                else:
                    policy[option] = value
        # add policy to the full list
        policies.append(policy)
    return policies

def get_links(device):
    links = []
    # send command to list all links
    cmd = 'link listnames'
    device.get_response(cmd)
    # parse the response
    matches = re.finditer(r"^(?P<link>\S+)\n", device.response, re.M)
    # for each match
    for match in matches:
        links.append(match.group('link'))
    return links

def get_scopes(device):
    scopes = []
    # send command to get all scopes
    cmd = 'scope list'
    device.get_response(cmd)
    #print(f"<pre>{device.response}</pre>")
    # parse the response
    matches = re.finditer(r"^(?P<name>\S+):\n"+
                          r"(?P<data>([ ]+.*\n)+)", device.response, re.M)
    # for each match
    for match in matches:
        # get the name
        name = match.group('name')
        # collect the data
        data = match.group('data')
        # get the subnet
        match = re.search(r"^[ ]+subnet = (?P<subnet>(\d{1,3}\.){3}\d{1,3}/\d{1,2})\b", data, re.M)
        if match is None:
            continue
        # create IP class
        subnet = n.IP(match.group('subnet'))
        # if this is not a valid subnet
        if not subnet.valid:
            continue
        first = subnet.nth(0)
        # get the policy
        match = re.search(r"^[ ]+policy = (?P<policy>\S+)", data, re.M)
        if match is None:
            continue
        policy = match.group('policy')
        # get the primary
        primary = None
        match = re.search(r"^[ ]+primary-subnet = (?P<primary>(\d{1,3}\.){3}\d{1,3}/\d{1,2})\b", data, re.M)
        if match is not None:
            primary = match.group('primary')
        # get the tag string
        match = re.search(r"^[ ]+selection-tag-list = (?P<tags>.*)", data, re.M)
        if match is None:
            continue
        tag_string = match.group('tags')
        # collect all tags
        tags = []
        matches = re.finditer(r"\{\d+[ ]+(?P<tag>\S+?)\}", tag_string, re.M)
        for match in matches:
            tags.append(match.group('tag'))
        # add info to the final list
        scope = {
                 'name': name, 'network': subnet.network, 'policy': policy, 'primary': primary, 'tags': sorted(tags), 'total': None, 'free': None, 'leased': None,
                 'first': subnet.nth(0, dec=True), 'last': subnet.nth('last', dec=True)
                }
        scopes.append(scope)
    # if any scopes were found
    if len(scopes) > 0:
        # send command to get all utilization
        cmd = 'report dhcpv4'
        device.get_response(cmd)
        # parse the response
        matches = re.finditer(r"^[ ]*(?P<subnet>(\d{1,3}\.){3}\d{1,3}/\d{1,2})[ ]+(?P<name>\S+)[ ]+\d+[ ]+(?P<total>\d+)[ ]+(?P<reserved>\d+)[ ]+"+
                              r"(?P<leased>\d+)[ ]+(?P<available>\d+)[ ]+(?P<other_available>\d+)", device.response, re.M)
        for match in matches:
            name = match.group('name')
            # match the utilization to the scope
            for i in range(len(scopes)):
                if scopes[i]['name'] == name:
                    scopes[i]['total'] = int(match.group('total'))
                    scopes[i]['leased'] = int(match.group('leased'))
                    scopes[i]['free'] = int(match.group('available')) + int(match.group('other_available'))
                    break
    return scopes

def get_prefixes(device):
    prefixes = []
    # send command to get all prefixes
    cmd = 'prefix list'
    device.get_response(cmd)
    #print(f"<pre>{device.response}</pre>")
    # parse the response
    matches = re.finditer(r"^(?P<name>\S+):\n"+
                          r"(?P<data>([ ]+.*\n)+)", device.response, re.M)
    # for each match
    for match in matches:
        # get the name
        name = match.group('name')
        # collect the data
        data = match.group('data')
        # get the prefix
        match = re.search(r"^[ ]+address = (?P<prefix>[\da-fA-F:]+/\d{1,3})\b", data, re.M)
        if match is None:
            continue
        # create IP class
        prefix = n.IP(match.group('prefix'))
        # if this is not a valid network
        if not prefix.valid:
            continue
        # get the policy
        match = re.search(r"^[ ]+policy = (?P<policy>\S+)", data, re.M)
        if match is None:
            continue
        policy = match.group('policy')
        # get the link
        link = None
        match = re.search(r"^[ ]+link = (?P<link>\S+)", data, re.M)
        if match is not None:
            link = match.group('link')
        # get the tag string
        match = re.search(r"^[ ]+selection-tags = (?P<tags>.*)", data, re.M)
        if match is None:
            continue
        tag_string = match.group('tags')
        # collect all tags
        tags = []
        matches = re.finditer(r"\{\d+[ ]+(?P<tag>\S+?)\}", tag_string, re.M)
        for match in matches:
            tags.append(match.group('tag'))
        first_hex, sec_hex, third_hex = prefix.first_three
        # add info to the final list
        prefix = {
                  'name': name, 'network': prefix.network, 'policy': policy, 'link': link, 'tags': sorted(tags), 'leased': None,
                  'first_hex': first_hex, 'sec_hex': sec_hex, 'third_hex': third_hex
                 }
        prefixes.append(prefix)
    # if any prefixes were found
    if len(prefixes) > 0:
        # send command to get all utilization
        cmd = 'report dhcpv6'
        device.get_response(cmd)
        # parse the response
        matches = re.finditer(r"^[ ]*(?P<prefix>[\da-fA-F:]+/\d{1,3})[ ]+(?P<name>\S+)[ ]+\S+[ ]+(?P<reserved>\d+)[ ]+(?P<leased>\d+)[ ]+"+
                              r"\d+[ ]+\d+[ ]+\d+[ ]+\d+[ ]+\d+[ ]+\d+[ ]+(?P<active_dynamic>\d+)[ ]+(?P<active_deactivated>\d+)", device.response, re.M)
        for match in matches:
            name = match.group('name')
            # match the utilization to the prefix
            for i in range(len(prefixes)):
                if prefixes[i]['name'] == name:
                    prefixes[i]['leased'] = int(match.group('leased'))
                    break
    return prefixes

