#!/usr/bin/python3.6
from bs4 import BeautifulSoup as soup
import requests
import json
import re

import parse as p
import networking as n

def getLoginInfo():
    # declare URL, username and password
    url = "https://ipam.charterlab.com:8443/incontrol/"
    user = "scriptapi"
    passwd = "readonly"
    # this info would be used like:
    ##import urllib3
    ##urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    ##with requests.Session() as s:
    ##  payload = {'username': user, 'password': passwd}
    ##  output = s.post(url+"authenticate.action", data=payload, verify=False)
    return [url, user, passwd]

def getDeviceID(session, url, hostname):
    # initialize ID variable
    containerID = -1
    # search IPControl for the hostname
    payload = { 'currentPage': '1', 'pageSize': '20', 'sortAsc': 'true',\
                'sortField': 'name', 'deviceField': 'hostname', 'deviceType': 'all',\
                'addressType': 'all', 'searchValue': hostname, 'compareType': 'exact'}
    output = session.post(url+"gwt/search/device.action", data=payload, verify=False)
    # format the response
    response = json.loads(output.text)
    # loop over the response
    for item in response['items']:
        # if the container name matches the hostname
        if item['hostname'].lower() == hostname.lower():
            # loop over each sub-container in the container
            for container in item['container']:
                # if the container content contains the hostname searched
                if container['content'] == hostname:
                    # strip the ID from the container link
                    containerID = container['href'].split("=")[1]
                    break
        # if the container ID was found
        if containerID != -1:
            # stop looking for the container ID
            break
    return containerID

def getDeviceIPs(session, url, containerID):
    # initialize IP arrays
    ipv4 = []
    ipv6 = []
    # load the device container
    payload = {'id': containerID}
    output = session.post(url+"container/show.do?view=container&showAllBlocks=false", data=payload, verify=False)
    # format the response
    response = soup(output.text, "html.parser")
    # find all table rows
    response = response.body.table
    ip_rows = response.findAll("tr")
    # loop over each row
    interface = ""
    for row in ip_rows:
        # if this row has a class
        if row.get("class"):
            # if this is an interface row
            if row.get("class") == ["bluetabledata"]:
                # store the interface name
                interface = row.td.text
                # modify the interface name
                interface = p.min_spaces(interface)
            # if this is an IP row
            elif row.get("class") == ["odd_sub"] or row.get("class") == ["even_sub"]:
                # get all columns of the row
                col = row.findAll("td")
                # find the IP assigned and the network
                ip = col[6].text.strip().split(' ')[0].strip()
                #subnet = col[2].a.b.text + col[3].text
                subnet = ip + col[3].text
                if ":" in ip:
                    subnet = n.nthIPv6(subnet, 0)
                else:
                    subnet = n.nthIPv4(subnet, 0)
                # collect the info found
                ipInfo = {"Interface": interface, "Assigned": ip.lower(), "Network": subnet.lower()}
                # store the data to the appropriate array
                if ":" in ip:
                    ipv6.append(ipInfo)
                else:
                    ipv4.append(ipInfo)
    return [ipv4, ipv6]

####################################################################################
api_url = "https://ipam.charterlab.com:8443/inc-rest/api/v1/"
gui_url = "https://ipam.charterlab.com:8443/incontrol/"
user = "api-rw"
passwd = "guppyfish1"

def getURLs():
    api_url = "https://ipam.charterlab.com:8443/inc-rest/api/v1/"
    gui_url = "https://ipam.charterlab.com:8443/incontrol/"
    return [api_url, gui_url]

def loginGUI(session):
    url = f"{gui_url}authenticate.action"
    payload = {'username': user, 'password': passwd}
    response = session.post(url, data=payload, verify=False)

def loginAPI(session):
    # create login URL
    url = f"{api_url}login"
    headers = {"Accept":"application/json", "Content-Type": "application/x-www-form-urlencoded"}
    login = f"username={user}&password={passwd}"
    # send login request
    response = session.post(url, headers=headers, data=login, verify=False)
    # get the login token
    access_token = response.json()['access_token']
    # update the headers for this session
    hdrs = {"Accept":"application/json", 'Authorization': 'Bearer ' + access_token}
    session.headers.update(hdrs)

def getZoneByIP(session, ip):
    zone = None
    # query IPControl
    url = f"{api_url}Gets/getDeviceByIPAddr?ipAddress=" + ip
    response = session.get(url, verify=False)
    # if a valid response was received
    if response.ok:
        # get the container name
        container = response.json().get('container')
        # if a container name was found
        if container is not None:
            # get the container hierarchy
            zone_data = container.split('/')
            # if container is nested 5 or more times
            if len(zone_data) >= 5:
                # if this is any of the main zones
                if zone_data[4][:2] in ['SA', 'SH', 'SC', 'SB']:
                    zone = zone_data[4][:2]
                else:
                    zone = zone_data[4]
                # if zone is exception
                if zone == 'SS-MO':
                    zone = 'SM'
            else:
                zone = zone_data[len(zone_data)-1]
            # remove '-CO' from the end of zone names
            match = re.search(r"^(?P<zone>.*?)(-CO)?$", zone, re.M)
            if match is not None:
                zone = match.group('zone')
    return zone

def getContainerIdByIP(session, ip):
    containerID = -1
    # query the API for the device data
    url = f"{api_url}Gets/getDeviceByIPAddr?ipAddress=" + ip
    response = session.get(url, verify=False)
    # if a valid response was received
    if response.ok:
        # translate the response to a JSON
        deviceData = response.json()
        # if the response contained the device container
        if deviceData.get('container') != None:
            # grab the container
            container = deviceData['container']
            # query the API for the container data
            url = f"{api_url}Gets/getContainerByName?containerName=" + container.replace("/","%2F").replace(" ","%20")
            response = session.get(url, verify=False)
            # if a valid response was received
            if response.ok:
                # translate the response to a JSON
                containerData = response.json()
                # if the response contains the container id
                if containerData.get('id'):
                    # store the container ID
                    containerID = containerData['id']
    return containerID

def getContainerNameByIP(session, ip):
    container = ""
    # query the API for the device data
    url = f"{api_url}Gets/getDeviceByIPAddr?ipAddress=" + ip
    response = session.get(url, verify=False)
    # if a valid response was received
    if response.ok:
        # translate the response to a JSON
        deviceData = response.json()
        # if the response contained the device container
        if deviceData.get('container') != None:
            # grab the container
            container = deviceData['container']
    return container

def getParentContainerId(session, ip):
    containerID = -1
    # query the API for the device data
    url = f"{api_url}Gets/getDeviceByIPAddr?ipAddress=" + ip
    response = session.get(url, verify=False)
    # if a valid response was received
    if response.ok:
        # translate the response to a JSON
        deviceData = response.json()
        # if the response contained the device container
        if deviceData.get('container') != None:
            # grab the container
            container = deviceData['container']
            parent = container[:container.rfind("/")]
            # query the API for the container data
            url = f"{api_url}Gets/getContainerByName?containerName=" + parent.replace("/","%2F").replace(" ","%20")
            response = session.get(url, verify=False)
            # if a valid response was received
            if response.ok:
                # translate the response to a JSON
                containerData = response.json()
                # if the response contains the container ID
                if containerData.get('id'):
                    # store the container ID
                    containerID = containerData['id']
    return containerID

def getInterfaces(session, deviceID, parentID):
    interfaces = []
    # request page with list of interfaces
    url = f"{gui_url}block/create.do?containerid={deviceID}&cparentid={parentID}&root=0"
    response = session.get(url, verify=False)
    # format the response
    response = soup(response.text, "html.parser")
    # get the interface list from the response
    interface_select = response.find("select", {"name": "blkinterface"})
    if interface_select != None:
        # get each option listed
        select_list = interface_select.findAll("option")
        # for each option listed
        for each in select_list[1:]:
            # store the values
            interface = {"id": each['value'], "Name": each.text}
            interfaces.append(interface)
    return interfaces

def getNetworkElementId(session, data):
    deviceID = -1
    # if the search is by IP address
    if n.validIPv4(data):
        url = f"{api_url}Gets/getNetworkElementByNameOrIpAddress?netElementIpAddress=" + data
    # if the search is by hostname
    else:
        url = f"{api_url}Gets/getNetworkElementByName?netElementName=" + data
    response = session.get(url, verify=False)
    # if a valid response was received
    if response.ok:
        # translate the response to a JSON
        networkData = response.json()
        # if the response contains the ID
        if networkData.get('id'):
            # store the ID
            deviceID = networkData['id']
    return deviceID

def addInterface(session, netDeviceID, interface):
    url = f"{gui_url}interface/save.do"
    # create interface data
    payload = {"displayCount": "1000",
                          "netelementid": str(netDeviceID),
                          "verb": "create",
                          "id": str(0),
                          "name": interface,
                          "status": str(1),
                          "vrfname": ""
                        }
    # send request
    response = session.post(url, data=payload, verify=False)
    return getMessages(response.text)

def deleteInterface(session, netDeviceID, interfaceID):
    messages = []
    url = f"{gui_url}gwt/interface/delete.do"
    # create interface data
    payload = {"selectedid": interfaceID,
                          "currentPage": "1",
                          "pageSize": "1000",
                          "netElementId": netDeviceID
                        }
    # send request
    response = session.post(url, data=payload, verify=False)
    # get the messages from the response
    responseData = response.json()
    if responseData.get('errors'):
        messages = responseData['errors']
    elif responseData.get('messages'):
        messages = responseData['messages']
    return messages

def getBlockByIpAddress(session, ip):
    # if this is an IPv6 address
    if ":" in ip:
        start_prefix = 127
    else:
        start_prefix = 31
    # get starting prefix
    network = ip.split("/")
    # if a prefix was supplied
    if len(network) > 1:
        # use the network ID as the ip
        ip = network[0]
        # start with the prefix supplied
        start_prefix = int(network[1])
    # get the block information
    blockID = -1
    blockName = ""
    blockType = ""
    # send the request
    url = f"{api_url}Gets/getBlockByIpAddress?ipAddress=" + ip
    response = session.get(url, verify=False)
    # while a block is not found
    prefix = start_prefix
    while not(response.ok) and prefix >= 1:
        if ":" not in ip:
            # increase the subnet size and calculate the new starting address
            newIP = n.nthIPv4(ip+"/"+str(prefix), 0).split("/")[0]
        # if this is an IPv6 address
        else:
            # increase the prefix size and calculate the new starting address
            newIP = n.nthIPv6(ip+"/"+str(prefix), 0).split("/")[0]
        # look for the new block calculated
        url = f"{api_url}Gets/getBlockByIpAddress?ipAddress={newIP}&bsize={prefix}"
        response = session.get(url, verify=False)
        # decrease the prefix size
        prefix -= 1
    # if a valid response was received
    if response.ok:
        # translate the response to a JSON
        blockData = response.json()
        # if the response contains the ID, name, type, and status
        if blockData.get('id') != None and blockData.get('blockName') != None and blockData.get('blockType') != None:
            # collect the necessary data
            blockID = blockData['id']
            blockName = blockData['blockName']
            blockType = blockData['blockType']
            blockStatus = blockData['blockStatus']
    return [blockID, blockName, blockType, blockStatus]

def getBlockByIpAddressContainerState(session, ip, containerName, desiredState):
# the container is only used if duplicate blocks are found in IPControl
# the state is only used if multiple blocks are found on the same container
    multiple = False
    # if this is an IPv6 address
    if ":" in ip:
        start_prefix = 127
    else:
        start_prefix = 31
    # get starting prefix
    network = ip.split("/")
    # if a prefix was supplied
    if len(network) > 1:
        # use the network ID as the ip
        ip = network[0]
        # start with the prefix supplied
        start_prefix = int(network[1])
    # get the block information
    blockID = -1
    blockName = ""
    blockType = ""
    # send the request
    url = f"{api_url}Gets/getBlockByIpAddress?ipAddress=" + ip
    response = session.get(url, verify=False)
    # while a block is not found
    prefix = start_prefix
    while not(response.ok) and prefix >= 1:
        if ":" not in ip:
            # increase the subnet size and calculate the new starting address
            newIP = n.nthIPv4(ip+"/"+str(prefix), 0).split("/")[0]
        # if this is an IPv6 address
        else:
            # increase the prefix size and calculate the new starting address
            newIP = n.nthIPv6(ip+"/"+str(prefix), 0).split("/")[0]
        # look for the new block calculated
        url = f"{api_url}Gets/getBlockByIpAddress?ipAddress={newIP}&bsize={prefix}"
        response = session.get(url, verify=False)
        # decrease the prefix size
        prefix -= 1
        # if multiple block were found
        if "Multiple blocks found" in response.text:
            multiple = True
            break
    # if multiple blocks were found
    if multiple:
        # determine if user is looking for free blocks or not
        # NOTE: this will return deployed and reserved even if a 'free' state is desired
        if desiredState.lower() == "free":
            desiredStates = ["free", "aggregate", "deployed", "reserved"]
        else:
            desiredStates = ["deployed", "reserved", "aggregate", "free"]
        # create the container name
        containerName += "/"
        # while a free block has not been found and there is containers left to check
        while not(response.ok) and "/" in containerName:
            # check the each container
            containerName = containerName[:containerName.rfind("/")]
            container = containerName.replace("/","%2F").replace(" ","%20")
            prefix = start_prefix
            # while this is not max prefix size
            while not(response.ok) and prefix > 1:
                # if this is an IPv4 address
                if ":" not in ip:
                    # increase the subnet size and calculate the new starting address
                    [newIP, newPrefix] = n.nthIPv4(ip+"/"+str(prefix), 0).split("/")
                # if this is an IPv6 address
                else:
                    # increase the prefix size and calculate the new starting address
                    [newIP, newPrefix] = n.nthIPv6(ip+"/"+str(prefix), 0).split("/")
                # send the search for the new network calculated
                url = f"{api_url}Gets/getBlockByIpAddress?ipAddress={newIP}&container={container}&bsize={prefix}"
                response = session.get(url, verify=False)
                # if multiple block were found
                if "Multiple blocks found" in response.text:
                    # for each desired state supplied
                    for state in desiredStates:
                        # look for blocks with the desired states
                        new_url = f"{url}&status={state}"
                        response = session.get(new_url, verify=False)
                        # if a valid response was received
                        if response.ok:
                            break
                # decrease the prefix size
                prefix -= 1
    # if a valid response was received
    if response.ok:
        # translate the response to a JSON
        blockData = response.json()
        # if the response contains the ID, name, type, and status
        if blockData.get('id') != None and blockData.get('blockName') != None and blockData.get('blockType') != None:
            # collect the necessary data
            blockID = blockData['id']
            blockName = blockData['blockName']
            blockType = blockData['blockType']
            blockStatus = blockData['blockStatus']
    return [blockID, blockName, blockType, blockStatus]

def addChildBlock(session, parentID, deviceID, interfaceID, blockID, blockName, blockType, network, offset):
    serviceID = -1
    # find the block type ID (servicetype)
    url = f"{gui_url}block/create.do?containerid={deviceID}&cparentid={parentID}&root=0"
    response = session.get(url, verify=False)
    # format the response
    response = soup(response.text, "html.parser")
    # get the interface list from the response
    service_select = response.find("select", {"name": "servicetype"})
    if service_select != None:
        # get each option listed
        select_list = service_select.findAll("option")
        # for each option listed
        for each in select_list[1:]:
            # if service text equals the block type
            if each.text == blockType:
                serviceID = each['value']
    # if the service ID was not found
    if serviceID == -1:
        print("Unable able to find service ID for \'{blockType}\'.")
        sys.exit(1)
    # determine the IP type
    if ":" not in network:
        ipType = "0"
    else:
        ipType = "1"
    # build JSON for HTML form
    payload = {"verb": "create",
                          "containerid": deviceID,
                          "rootblock": "0",
                          "root": "0",
                          "refresh": "",
                          "nextid": "0",
                          "parentName": blockName + " (" + blockType + ")",
                          "blkinterface": interfaceID,
                          "servicetype": serviceID,
                          "v4v6both": ipType,
                          "blocksize": network.split("/")[1],
                          "defaultAllocation": "0",
                          "manual": "1",
                          "parentblockid": blockID,
                          "sortAsc": "1",
                          "inheritdiscoveryagent": "2",
                          "numipaddresses": "1",
                          "numberofipaddresses": "1",
                          "interfaceip1": "0",
                          "ipoffset1": offset,
                          "interfaceip2": "0",
                          "ipoffset2": "2",
                          "interfaceip3": "0",
                          "ipoffset3": "3",
                          "interfaceip4": "0",
                          "ipoffset4": "4",
                          "interfaceip5": "0",
                          "ipoffset5": "5",
                          "interfaceip6": "0",
                          "ipoffset6": "6",
                          "interfaceip7": "0",
                          "ipoffset7": "7",
                          "interfaceip8": "0",
                          "ipoffset8": "8",
                          "addrspace": network.split("/")[0],
                          "name": network,
                          "notes": "API",
                          "blockstatus": "4",
                          "swipname": "",
                          "reasoncode": "0",
                          "reasonnotes": "",
                          "addrpooltemplate": "-1",
                          "subnet.id": "",
                          "defaultGateway": "",
                          "failoverNetserviceId": "-1",
                          "primaryWinsServer": "",
                          "dhcpPolicySetId": "-1",
                          "dhcpOptionSetId": "-1",
                          "idnformat": "on"
                        }
    # add the network to the device
    url = f"{gui_url}block/allocate.do"
    response = session.post(url, data=payload, verify=False)
    # get the return messages
    messages = getMessages(response.text)
    return messages

def attachChildBlock(session, parentID, deviceID, interfaceID, blockType, network, offset):
    serviceID = -1
    # find the block type ID (servicetype)
    url = f"{gui_url}block/create.do?containerid={deviceID}&cparentid={parentID}&root=0"
    response = session.get(url, verify=False)
    # format the response
    response = soup(response.text, "html.parser")
    # get the interface list from the response
    service_select = response.find("select", {"name": "servicetype"})
    if service_select != None:
        # get each option listed
        select_list = service_select.findAll("option")
        # for each option listed
        for each in select_list[1:]:
            # if service text equals the block type
            if each.text == blockType:
                serviceID = each['value']
    # if the service ID was not found
    if serviceID == -1:
        print("Unable able to find service ID for \'{blockType}\'.")
        sys.exit(1)
    # determine the IP type
    if ":" not in network:
        ipType = "0"
    else:
        ipType = "1"
    # build JSON for HTML form
    payload = {"verb": "create",
                          "containerid": deviceID,
                          "id": deviceID,
                          "cparentid": parentID,
                          "refresh": "",
                          "v4v6both": ipType,
                          "blocksize": network.split("/")[1],
                          "servicetype": serviceID,
                          "manual": "1",
                          "blockname": network,
                          "blkinterface": interfaceID,
                          "numipaddresses": "1",
                          "numberofipaddresses": "1",
                          "interfaceip1": "0",
                          "ipoffset1": offset,
                          "interfaceip2": "0",
                          "ipoffset2": "2",
                          "interfaceip3": "0",
                          "ipoffset3": "3",
                          "interfaceip4": "0",
                          "ipoffset4": "4",
                          "interfaceip5": "0",
                          "ipoffset5": "5",
                          "interfaceip6": "0",
                          "ipoffset6": "6",
                          "interfaceip7": "0",
                          "ipoffset7": "7",
                          "interfaceip8": "0",
                          "ipoffset8": "8"
                        }
    # add the network to the device
    url = f"{gui_url}block/attachsave.do"
    response = session.post(url, data=payload, verify=False)
    # get the return messages
    return getMessages(response.text)

def deleteBlock(session, parentID, deviceID, blockID):
    url = f"{gui_url}block/multidelete.do"
    payload = {"verb": "edit",
                          "id": deviceID,
                          "containerid": deviceID,
                          "cparentid": parentID,
                          "showAllBlocks": "false",
                          "selectedid": blockID
                        }
    response = session.post(url, data=payload, verify=False)
    # get the return messages
    messages = getMessages(response.text)
    return messages

def getMessages(output):
    messages = []
    message_section = ""
    # find the message section
    patternString = "^<script\ type=\"text/javascript\">(?P<message_section>.*?)</script>"
    pattern = re.compile(patternString, re.MULTILINE | re.VERBOSE | re.DOTALL)
    matches = re.finditer(pattern, output)
    for match in matches:
        message_section = match.group("message_section")
    # find each message in the message section
    patternString = "\"(?P<message>.*?)\""
    pattern = re.compile(patternString)
    matches = re.finditer(pattern, message_section)
    for match in matches:
        message = match.group("message")
        messages.append(message)
    return messages

