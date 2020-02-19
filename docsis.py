#!/usr/bin/python3.6

import arris_e6000 as e6000
import casa_c100g as c100g
import cisco_cbr8 as cbr8
import nokia_7360 as n7360
import nokia_sc2d as sc2d
import adtran_9504N as a9504N
import adtran_9516 as a9516
import nokia_gac as gac

###################################################################################
## CM
###################################################################################

def isDeviceOnline(session, expec, queryValue, queryType, deviceType):
    if deviceType == "E6000":
        [online, cm_mac] = e6000.isDeviceOnline(session, expec, queryValue, queryType)
    elif deviceType == "C100G":
        [online, cm_mac] = c100g.isDeviceOnline(session, expec, queryValue, queryType)
    elif deviceType == "CBR8":
        [online, cm_mac] = cbr8.isDeviceOnline(session, expec, queryValue, queryType)
    return [online, cm_mac]

def getCM_phy(session, expec, cm_mac, deviceType):
    if deviceType == "E6000":
        phy = e6000.getCM_phy(session, expec, cm_mac)
    elif deviceType == "C100G":
        phy = c100g.getCM_phy(session, expec, cm_mac)
    elif deviceType == "CBR8":
        phy = cbr8.getCM_phy(session, expec, cm_mac)
    return phy

def getCM_ip(session, expec, cm_mac, deviceType):
    if deviceType == "E6000":
        ip = e6000.getCM_ip(session, expec, cm_mac)
    elif deviceType == "C100G":
        ip = c100g.getCM_ip(session, expec, cm_mac)
    elif deviceType == "CBR8":
        ip = cbr8.getCM_ip(session, expec, cm_mac)
    return ip

def getCM_macDomain(session, expec, cm_mac, deviceType):
    if deviceType == "E6000":
        mac_domain = e6000.getCM_macDomain(session, expec, cm_mac)
    elif deviceType == "C100G":
        mac_domain = c100g.getCM_macDomain(session, expec, cm_mac)
    elif deviceType == "CBR8":
        mac_domain = cbr8.getCM_macDomain(session, expec, cm_mac)
    return mac_domain

def testPing(session, expec, ip, count, fail_threshold, deviceType):
    if deviceType == "E6000":
        success = e6000.testPing(session, expec, ip, count, fail_threshold)
    elif deviceType == "C100G":
        success = c100g.testPing(session, expec, ip, count, fail_threshold)
    elif deviceType == "CBR8":
        success = cbr8.testPing(session, expec, ip, count, fail_threshold)
    return success

###################################################################################
## Global
###################################################################################

def noPaging(session, expec, deviceType):
    if deviceType=="E6000":
        e6000.noPaging(session, expec)
    elif deviceType=="C100G":
        c100g.noPaging(session, expec)
    elif deviceType=="CBR8":
        cbr8.noPaging(session, expec)

def getHostname(session, deviceType):
    if deviceType=="E6000":
        cmd = "terminal length 0"
        hostname = e6000.getHostname(session, cmd)
    elif deviceType=="C100G":
        cmd = "page-off"
        hostname = c100g.getHostname(session, cmd)
    elif deviceType=="CBR8":
        cmd = "terminal length 0"
        hostname = cbr8.getHostname(session, cmd)
    elif deviceType=="SC2D":
        cmd = ""
        hostname = sc2d.getHostname(session, cmd)
    elif deviceType=="9504N":
        cmd = "terminal length 0"
        hostname = a9504N.getHostname(session, cmd)
    elif deviceType=="9516":
        cmd = "terminal length 0"
        hostname = a9516.getHostname(session, cmd)
    return hostname

def getSwVersion(session, expec, deviceType):
    if deviceType=="E6000":
        version = e6000.getSwVersion(session, expec)
    elif deviceType=="C100G":
        version = c100g.getSwVersion(session, expec)
    elif deviceType=="CBR8":
        version = cbr8.getSwVersion(session, expec)
    elif deviceType=="SC2D":
        version = sc2d.getSwVersion(session, expec)
    elif deviceType=="7360":
        version = n7360.getSwVersion(session, expec)
    elif deviceType=="9504N":
        version = a9504N.getSwVersion(session, expec)
    elif deviceType=="9516":
        version = a9516.getSwVersion(session, expec)
    return version

def ipConnectivity(device, ip_srcs, ip_dest):
    results = []
    if device.model == 'E6000':
        results = e6000.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == 'C100G':
        results = c100g.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == 'CBR8':
        results = cbr8.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == 'SC2D':
        results = sc2d.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == '9504N':
        results = a9504N.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == '9516':
        results = a9516.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == 'GAC':
        results = gac.ipConnectivity(device, ip_srcs, ip_dest)
    elif device.model == '7360':
        results = n7360.ipConnectivity(device, ip_srcs, ip_dest)
    return results

def channelStatus(device, mac, DS, US):
    dsStatus = []
    usStatus = []
    if device.model == 'E6000':
        [dsStatus, usStatus] = e6000.channelStatus(device, mac, DS, US)
    elif device.model == 'C100G':
        [dsStatus, usStatus] = c100g.channelStatus(device, mac, DS, US)
    elif device.model == 'CBR8':
        [dsStatus, usStatus] = cbr8.channelStatus(device, mac, DS, US)
    elif device.model == 'SC2D':
        [dsStatus, usStatus] = sc2d.channelStatus(device, mac, DS, US)
    elif device.model == '9504N':
        [dsStatus, usStatus] = a9504N.channelStatus(device, mac, DS, US)
    elif device.model == '9516':
        [dsStatus, usStatus] = a9516.channelStatus(device, mac, DS, US)
    elif device.model == 'GAC':
        [dsStatus, usStatus] = gac.channelStatus(device, mac)
    elif device.model == '7360':
        [dsStatus, usStatus] = n7360.channelStatus(device, mac)
    return [dsStatus, usStatus]

def getMCounts(device, mac, multicasts):
    mcounts = []
    if device.model == 'E6000':
        mcounts = e6000.getMCounts(device, multicasts)
    elif device.model == 'C100G':
        mcounts = c100g.getMCounts(device, multicasts)
    elif device.model == 'CBR8':
        mcounts = cbr8.getMCounts(device, multicasts)
    elif device.model == 'SC2D':
        mcounts = sc2d.getMCounts(device, mac, multicasts)
    elif device.model == 'GAC':
        mcounts = gac.getMCounts(device, mac, multicasts)
    mcounts.sort(key=tunnelKey)
    return mcounts

def getDSGcounts(device, DS, mac, tunnels):
    count = []
    if device.model == 'E6000':
        count = e6000.getDSGcounts(device, DS, tunnels)
    elif device.model == 'C100G':
        count = c100g.getDSGcounts(device, DS, mac, tunnels)
    elif device.model == 'CBR8':
        count = cbr8.getDSGcounts(device, DS, tunnels)
    elif device.model == 'SC2D':
        count = sc2d.getDSGcounts(device, mac, tunnels)
    count.sort(key=tunnelKey)
    return count

def getSNR(device, US, mac):
    snr = []
    if device.model == 'E6000':
        snr = e6000.getSNR(device, mac, US)
    elif device.model == 'C100G':
        snr = c100g.getSNR(device, US)
    elif device.model == 'CBR8':
        snr = cbr8.getSNR(device, US)
    elif device.model == 'SC2D':
        snr = sc2d.getSNR(device, mac)
    elif device.model == 'GAC':
        snr = gac.getSNR(device, mac)
    return snr

def cmCount(device, mac, DS, US):
    count = {'online': 0, 'total': 0}
    if device.model == 'E6000':
        count = e6000.cmCount(device, mac)
    elif device.model == 'C100G':
        count = c100g.cmCount(device, US)
    elif device.model == 'CBR8':
        count = cbr8.cmCount(device, DS)
    elif device.model == 'SC2D':
        count = sc2d.cmCount(device, mac)
    elif device.model == '9504N':
        count = a9504N.cmCount(device, mac)
    elif device.model == '9516':
        count = a9516.cmCount(device, mac)
    elif device.model == 'GAC':
        count = gac.cmCount(device, mac)
    elif device.model == '7360':
        count = n7360.cmCount(device, mac)
    return count

def cmCountTotal(session, expec, deviceType):
    count = {'online': 0, 'total': 0}
    if deviceType=="E6000":
        count = e6000.cmCountTotal(session, expec)
    elif deviceType=="C100G":
        count = c100g.cmCountTotal(session, expec)
    elif deviceType=="CBR8":
        count = cbr8.cmCountTotal(session, expec)
    elif deviceType=="7360":
        count = n7360.cmCountTotal(session, expec)
    elif deviceType=="9504N":
        count = a9504N.cmCountTotal(session, expec)
    elif deviceType=="9516":
        count = a9516.cmCountTotal(session, expec)
    return count

def tunnelKey(json):
    try:
        return json['tunnel']
    except:
        return '0'

def clearModems(session, expec, deviceType):
    if deviceType=="E6000":
        e6000.clearModems(session, expec)
    elif deviceType=="C100G":
        c100g.clearModems(session, expec)
    elif deviceType=="CBR8":
        cbr8.clearModems(session, expec)

###############
##### NEW #####
###############

def get_version(device):
    version = 'Unknown'
    if device.model == 'E6000':
        version = e6000.get_version(device)
    elif device.model == 'C100G':
        version = c100g.get_version(device)
    elif device.model == 'CBR8':
        version = cbr8.get_version(device)
    elif device.model == 'SC2D':
        version = sc2d.get_version(device)
    elif device.model == '7360':
        version = n7360.get_version(device)
    elif device.model == '9504N':
        version = a9504N.get_version(device)
    elif device.model == '9516':
        version = a9516.get_version(device)
    elif device.model == 'GAC':
        version = gac.get_version(device)
    return version

############################################################
############### DOCSIS #####################################
############################################################
## Chassis
def get_total_cm_count(device):
    count = {'online': 0, 'total': 0}
    if device.model == 'E6000':
        count = e6000.get_total_cm_count(device)
    elif device.model == 'C100G':
        count = c100g.get_total_cm_count(device)
    elif device.model == 'CBR8':
        count = cbr8.get_total_cm_count(device)
    elif device.model == 'SC2D':
        count = sc2d.get_total_cm_count(device)
    elif device.model == '7360':
        count = n7360.get_total_cm_count(device)
    elif device.model == '9504N':
        count = a9504N.get_total_cm_count(device)
    elif device.model == '9516':
        count = a9516.get_total_cm_count(device)
    elif device.model == 'GAC':
        count = gac.get_total_cm_count(device)
    return count

## MAC Domain
def get_mac_domains(device):
    macs = []
    if device.model == 'E6000':
        macs = e6000.get_mac_domains(device)
    elif device.model == 'C100G':
        macs = c100g.get_mac_domains(device)
    elif device.model == 'CBR8':
        macs = cbr8.get_mac_domains(device)
    elif device.model == '9504N':
        macs = a9504N.get_mac_domains(device)
    elif device.model == '9516':
        macs = a9516.get_mac_domains(device)
    elif device.model == '7360':
        macs = n7360.get_mac_domains(device)
    elif device.model == 'GAC':
        macs = gac.get_mac_domains(device)
    return macs

def get_mac_description(device, mac):
    description = None
    if device.model == 'E6000':
        description = e6000.get_mac_description(device, mac)
    elif device.model == 'C100G':
        description = c100g.get_mac_description(device, mac)
    elif device.model == 'CBR8':
        description = cbr8.get_mac_description(device, mac)
    elif device.model == '9504N':
        description = a9504N.get_mac_description(device, mac)
    elif device.model == '9516':
        description = a9516.get_mac_description(device, mac)
    elif device.model == '7360':
        description = n7360.get_mac_description(device, mac)
    elif device.model == 'GAC':
        description = gac.get_mac_description(device, mac)
    return description

def get_mac_DS_US(device, mac):
    DS = None
    US = None
    if device.model == 'E6000':
        DS, US = e6000.get_mac_DS_US(device, mac)
    elif device.model == 'C100G':
        DS, US = c100g.get_mac_DS_US(device, mac)
    elif device.model == 'CBR8':
        DS, US = cbr8.get_mac_DS_US(device, mac)
    elif device.model == '9504N':
        DS, US = a9504N.get_mac_DS_US(device, mac)
    elif device.model == '9516':
        DS, US = a9516.get_mac_DS_US(device, mac)
    elif device.model == '7360':
        DS, US = n7360.get_mac_DS_US(device, mac)
    elif device.model == 'GAC':
        DS, US = gac.get_mac_DS_US(device, mac)
    return DS, US

def get_mac_connector(device, US):
    connector = None
    if device.model == 'E6000':
        connector = e6000.get_mac_connector(device, US)
    return connector

def get_mac_channel_counts(device, mac):
    counts = {'DS': 0, 'US': 0, 'OFDM': 0}
    if device.model == 'E6000':
        counts = e6000.get_mac_channel_counts(device, mac)
    elif device.model == 'C100G':
        counts = c100g.get_mac_channel_counts(device, mac)
    elif device.model == 'CBR8':
        counts = cbr8.get_mac_channel_counts(device, mac)
    elif device.model == '9504N':
        counts = a9504N.get_mac_channel_counts(device, mac)
    elif device.model == '9516':
        counts = a9516.get_mac_channel_counts(device, mac)
    elif device.model == '7360':
        counts = n7360.get_mac_channel_counts(device, mac)
    elif device.model == 'GAC':
        counts = gac.get_mac_channel_counts(device, mac)
    return counts

def get_mac_cm_counts(device, mac, DS, US):
    counts = {'online': 0, 'total': 0, 'percent': 100}
    if device.model == 'E6000':
        counts = e6000.get_mac_cm_counts(device, mac)
    elif device.model == 'C100G':
        counts = c100g.get_mac_cm_counts(device, US)
    elif device.model == 'CBR8':
        counts = cbr8.get_mac_cm_counts(device, DS)
    elif device.model == '9504N':
        counts = a9504N.get_mac_cm_counts(device, DS)
    elif device.model == '9516':
        counts = a9516.get_mac_cm_counts(device, DS)
    elif device.model == '7360':
        counts = n7360.get_mac_cm_counts(device, DS)
    elif device.model == 'GAC':
        counts = gac.get_mac_cm_counts(device, mac)
    return counts

def get_mac_IP_interface(device, mac):
    interface = None
    if device.model == 'E6000':
        interface = e6000.get_mac_IP_interface(device, mac)
    elif device.model == 'C100G':
        interface = c100g.get_mac_IP_interface(device, mac)
    elif device.model == 'CBR8':
        interface = cbr8.get_mac_IP_interface(device, mac)
    elif device.model == '9504N':
        interface = a9504N.get_mac_IP_interface(device, mac)
    elif device.model == '9516':
        interface = a9516.get_mac_IP_interface(device, mac)
    elif device.model == '7360':
        interface = n7360.get_mac_IP_interface(device, mac)
    elif device.model == 'GAC':
        interface = gac.get_mac_IP_interface(device, mac)
    return interface

def get_mac_IPs(device, mac):
    ipv4 = []
    ipv6 = []
    ipv4helper = []
    ipv6helper = []
    if device.model == 'E6000':
        ipv4, ipv4helper, ipv6, ipv6helper = e6000.get_mac_IPs(device, mac)
    elif device.model == 'C100G':
        ipv4, ipv4helper, ipv6, ipv6helper = c100g.get_mac_IPs(device, mac)
    elif device.model == 'CBR8':
        ipv4, ipv4helper, ipv6, ipv6helper = cbr8.get_mac_IPs(device, mac)
    elif device.model == '9504N':
        ipv4, ipv4helper, ipv6, ipv6helper = a9504N.get_mac_IPs(device, mac)
    elif device.model == '9516':
        ipv4, ipv4helper, ipv6, ipv6helper = a9516.get_mac_IPs(device, mac)
    elif device.model == '7360':
        ipv4, ipv4helper, ipv6, ipv6helper = n7360.get_mac_IPs(device, mac)
    elif device.model == 'GAC':
        ipv4, ipv4helper, ipv6, ipv6helper = gac.get_mac_IPs(device, mac)
    return ipv4, ipv4helper, ipv6, ipv6helper

def get_mac_DSG_tunnels(device, DS):
    tunnels = []
    if device.model == 'E6000':
        tunnels = e6000.get_mac_DSG_tunnels(device, DS)
    elif device.model == 'C100G':
        tunnels = c100g.get_mac_DSG_tunnels(device, DS)
    elif device.model == 'CBR8':
        tunnels = cbr8.get_mac_DSG_tunnels(device, DS)
    elif device.model == 'GAC':
        tunnels = gac.get_mac_DSG_tunnels(device, DS)
    return tunnels

def get_mac_video_interface(device, DS):
    interface = None
    if device.model == 'E6000':
        interface = e6000.get_mac_video_interface(device, DS)
    elif device.model == 'C100G':
        interface = c100g.get_mac_video_interface(device, DS)
    elif device.model == 'CBR8':
        interface = cbr8.get_mac_video_interface(device, DS)
    elif device.model == 'GAC':
        interface = gac.get_mac_video_interface(device, DS)
    return interface

def get_mac_video(device, DS):
    video = {}
    if device.model == 'E6000':
        video = e6000.get_mac_video(device, DS)
    elif device.model == 'C100G':
        video = c100g.get_mac_video(device, DS)
    elif device.model == 'CBR8':
        video = cbr8.get_mac_video(device, DS)
    return video

############################################################
############### CM #########################################
############################################################
class Modem:
    def __init__(self, mac, device=None):
        self.output = None
        self.__mac = mac
        self.__device = device
        self.__state = None
        self.__ipv4 = None
        self.__ipv6 = None
        self.__snr = None
    def __repr__(self):
        """ to be used as representation for developers """
        return f"CM({self.mac})"
    def __str__(self):
        """ returns 'mac' address """
        return f"{self.mac}"
    @property
    def mac(self):
        """ returns the MAC address of the CM """
        return self.__mac
    @mac.setter
    def mac(self, value):
        self.__mac = value
    @property
    def device(self):
        """ returns the device the CM currently resides on """
        return self.__device
    @device.setter
    def device(self, value):
        self.__device = value
    @property
    def state(self):
        """ returns the state of the modem """
        return self.__state
    @state.setter
    def state(self, value):
        self.__state = value
    @property
    def ipv4(self):
        """ returns the IPv4 address of the modem """
        return self.__ipv4
    @ipv4.setter
    def ipv4(self, value):
        self.__ipv4 = value
    @property
    def ipv6(self):
        """ returns the IPv6 address of the modem """
        return self.__ipv6
    @ipv6.setter
    def ipv6(self, value):
        self.__ipv6 = value
    @property
    def offline(self):
        """ returns True if the CM is offline """
        return self.__offline
    @offline.setter
    def offline(self, value):
        self.__offline = value

def get_modem(device, query_value, query_type):
    # create a new modem class
    modem = Modem(None)
    if device.model == 'E6000':
        e6000.get_modem(device, modem, query_value, query_type)
    elif device.model == 'C100G':
        c100g.get_modem(device, modem, query_value, query_type)
    elif device.model == 'CBR8':
        cbr8.get_modem(device, modem, query_value, query_type)
    elif device.model == '9504N':
        a9504N.get_modem(device, modem, query_value, query_type)
    elif device.model == '9516':
        a9516.get_modem(device, modem, query_value, query_type)
    elif device.model == '7360':
        n7360.get_modem(device, modem, query_value, query_type)
    elif device.model == 'GAC':
        gac.get_modem(device, modem, query_value, query_type)
    return modem

