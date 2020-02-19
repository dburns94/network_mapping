#!/usr/bin/python3.6

import sys
import json
import rethinkdb_ext as r_ext
import pexpect_ext as p_ext
import parseString as ps

import time
# device info gathering
def getHostname(session, cmd):
    hostname = ""
    return hostname

def getSwVersion(session, expec):
    version = "Unknown"
    return version

def ipConnectivity(session, expec, ips, iphelper):
    results = []
    # login to the packet engine
    pe_expec = "GS-MX80>"
    cmd = "pe-cli"
    lines = p_ext.sendCMD(session, cmd, "Password:", 15)
    cmd = "Gainspeed"
    lines = p_ext.sendCMD(session, cmd, pe_expec, 15)
    # turn off width paging
    cmd = "set cli screen-width 1000"
    lines = p_ext.sendCMD(session, cmd, pe_expec, 15)
    # run pings
    for ip in ips:
        if ip['check']:
            ipType = ""
            ip = ip['address']
            sys.stdout.write(".")
            if ":" in ip:
                ipType = "inet6 "
            cmd = "ping "+ipType+iphelper+" source "+ip.split("/")[0]+" count 3"
            lines = p_ext.sendCMD(session, cmd, pe_expec, 15)
            for i in lines[1:-1]:
                if "packets transmitted" in i:
                    i = ps.minSpaces(i)
                    recieved = int(ps.returnN(i,3))
                    transmitted = int(ps.returnN(i,0))
                    results.append({'ip': ip, 'recieved': recieved, 'transmitted': transmitted})
    # exit the packet engine
    cmd = "exit"
    lines = p_ext.sendCMD(session, cmd, expec, 15)
    return results

def channelStatus(session, expec, mac, DS, US):
    dsStatus = []
    usStatus = []
    return [dsStatus, usStatus]

def getMCounts(session, expec, mac, multicasts):
    counts = []
    # send command (takes about 35-40 seconds for remote sites)
    cmd = "show network "+mac["Slot"]+" downstream-classifier action mcast | display json | nomore"
    lines = p_ext.sendCMD(session, cmd, expec, 45)
    # convert output to json variable
    array = ps.array2json(lines[1:-2])
    # loop over json to find multicast counts
    for i in multicasts:
        for node in array["data"]["node-oper-data:network"]:
            if node["slot"] == mac["Slot"]:
                keepLooking = True
                for mcast in node["downstream-classifier"]:
                    if keepLooking:
                        for key in mcast["key-list"]:
                            if key["value"] == i["multicast"]:
                                sys.stdout.write('.')
                                keepLooking = False
                                counts.append({'multicast': {'multicast': i['multicast'], 'source': i['source']}, 'count': mcast["matches"], 'type': i['type'], 'tunnel': i['tunnel']})
                                break
    return counts

def getDSGcounts(session, expec, mac, tunnels):
    count = []
    return count

def getSNR(session, expec, mac):
    snr = []
    # send command
    cmd = "show ccap chassis slot "+mac["Slot"]+" rf-line-card us-rf-port "+mac["Port"]+" upstream-physical-channel counter snr | tab | nomore"
    lines = p_ext.sendCMD(session, cmd, expec, 15)
    # convert output to table array
    [col, table] = ps.parseTable(lines[2:-2])
    # loop over table contents and collect SNR stats
    for row in table[1:]:
        channelSNR = float(row[col["SNR"]])
        if channelSNR > 0:
            snr.append({'channel': row[col["INDEX"]], 'snr': round(channelSNR,1)})
    return snr

def cmCount(session, expec, mac):
    count = {"online": 0, "total": 0}
    # send command
    cmd = "show cable "+mac["Slot"]+" "+mac["Port"]+" summary | tab | nomore"
    lines = p_ext.sendCMD(session, cmd, expec, 15)
    # convert output to table array
    [col, table] = ps.parseTable(lines[3:-2])
    # loop over table contents and find CM counts
    for row in table:
        if row[col["SLOT"]] == mac["Slot"] and row[col["PORT"]]:
            count["online"] = int(row[col["ONLINE"]])
            count["total"] = int(row[col["DEVICES"]])
    return count

#def cmCountTotal(session, expec):
#  return count

# CMTS operations
#def clearModems(session, expec):

