#!/usr/bin/python3.6

import re
from networking import validIPv4, validIPv6

def compile(pattern):
    return re.compile(pattern, re.MULTILINE | re.VERBOSE)
    #return re.compile(pattern, re.MULTILINE)

def getMatch(output, pattern):
    match = None
    # if the output is a single string
    if type(output) == str:
        match = re.search(pattern, output, re.MULTILINE)
    # if the output is an array of strings
    elif type(output) == list:
        # for each string in the output
        for line in output:
            # look for a match
            match = re.search(pattern, line)
            # if there is a match
            if match != None:
                # stop looking
                break
    return match

def getMatches(output, pattern):
    # if the output is a single string
    if type(output) == str:
        matches = re.finditer(pattern, output, re.MULTILINE)
    # if the output is an array of strings
    elif type(output) == list:
        matches = []
        # for each string in the output
        for line in output:
            # look for a match
            match = re.search(pattern, line)
            # if there is a match
            if match != None:
                # add it to the matches
                matches.append(match)
    return matches

def negateMatches(output, pattern):
    cmds = []
    # get matches
    matches = getMatches(output, pattern)
    # for each match found
    for match in matches:
        # add the negate command
        cmds.append("no %s" % match.group(0))
    return cmds

def getMACs(output):
    macs = []
    # MAC pattern
    pattern = r"\b(([0-9a-fA-f]{4}\.){2}[0-9a-fA-f]{4}|([0-9a-fA-f]{2}:){5}[0-9a-fA-f]{2})\b"
    # get matches
    matches = getMatches(output, pattern)
    # for each match found
    for match in matches:
        # add the MAC to the results
        macs.append(match.group(0))
    return macs

def getIPv4(output):
    ipv4 = []
    # IPv4 pattern
    pattern = r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
    # get matches
    matches = getMatches(output, pattern)
    # for each match found
    for match in matches:
        ip = match.group(0)
        # if this is a valid IPv4 address
        if validIPv4(ip):
            # add the address to the results
            ipv4.append(ip)
    return ipv4

def getIPv6(output):
    ipv6 = []
    # IPv6 pattern
    pattern = r"(?!:)\b[0-9a-fA-F:]+:[0-9a-fA-F:]*[0-9a-fA-F:]+\b(?!:)"
    # get matches
    matches = getMatches(output, pattern)
    # for each match found
    for match in matches:
        ip = match.group(0)
        # if this is a valid IPv6 address
        if validIPv6(ip):
            # add the address to the results
            ipv6.append(ip)
    return ipv6

def getUniqueIPv4(output):
    ipv4 = []
    # IPv4 pattern
    pattern = r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
    # get matches
    matches = getMatches(output, pattern)
    # for each match found
    for match in matches:
        ip = match.group(0)
        # if this is a valid IPv4 address
        if ip not in ipv4 and validIPv4(ip):
            # add the address to the results
            ipv4.append(ip)
    return ipv4

def getUniqueIPv6(output):
    ipv6 = []
    # IPv6 pattern
    pattern = r"(?!:)\b[0-9a-fA-F:]+:[0-9a-fA-F:]*[0-9a-fA-F:]+\b(?!:)"
    # get matches
    matches = getMatches(output, pattern)
    # for each match found
    for match in matches:
        ip = match.group(0)
        # if this is a valid IPv6 address
        if ip not in ipv6 and validIPv6(ip):
            # add the address to the results
            ipv6.append(ip)
    return ipv6

