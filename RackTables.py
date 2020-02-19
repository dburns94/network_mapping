#!/usr/bin/python3.6

import requests
from bs4 import BeautifulSoup as soup

def getRTLogin(passFile):
    with open(passFile, "r") as inFile:
        for line in inFile:
            passwd = line[0:len(line)-1:1]
            break
    return passwd

url = "http://vidadev.charterlab.com/racktables/"
user = 'whoami'
passwd = getRTLogin('/var/www/html/files/pass/whoami')

def login(session):
    setAuthorization(session, url, user, passwd)

def getLoginInfo():
    # declare URL, username and password
    url = "http://vidadev.charterlab.com/racktables/"
    user = "whoami"
    passwd = getRTLogin("/var/www/html/files/pass/whoami")
    # this info would be used like:
    ##with requests.Session() as s:
    ##  rt.setAuthorization(s, url, user, passwd)
    return [url, user, passwd]

def setAuthorization(session, url, user, passwd):
# set the authorization string in the session headers
# this is to prevent the need for authentication throughout the session
    # login to RackTables
    response = session.get(url, auth=(user, passwd))
    # update the session headers with the authorization string
    session.headers.update({"Authorization": response.request.headers["Authorization"]})

def getDeviceLocationByName(session, hostname):
    # get device ID from RackTables
    deviceID = getDeviceID(session, url, hostname)
    # if the device was found in RackTables
    if deviceID != -1:
        # get rack location from RackTables
        location = getDeviceLocation(session, url, deviceID)
    else:
        location = None
    return location

def getDeviceID(session, url, hostname):
    # initialize ID variable
    deviceID = -1
    # search RackTables for hostname
    response = session.get(url+"index.php?page=search&last_tab=properties&q="+hostname)
    # format the response
    output = soup(response.text, "html.parser")
    # get the header links
    headerLinks = output.body.div.find("div", {"class": "menubar"}).findAll("a")
    # loop over the header links
    for link in headerLinks:
        # if the link is for the hostname searched
        if link.text.strip() == hostname:
            # find the parameters in the device link
            deviceParams = link["href"].split("?")[1].split("&")
            # loop over the parameters
            for param in deviceParams:
                [field, value] = param.split("=")
                # if this paramter is the object ID
                if field == "object_id":
                    # store the value
                    deviceID = value
            break
    # if the device link is not in the header
    if deviceID == -1:
        # find all sections of the results
        sections = output.body.div.find("div", {"class": "pagebar"}).findAll("div", {"class": "portlet"})
        # loop over each section to find the Objects section
        for section in sections:
            if section.h2.text == "Objects":
                # find all links in the section
                links = section.table.findAll("a")
                # loop over each link in the section
                for link in links:
                    try:
                        # if the link text is the hostname being searched
                        if link.strong.text == hostname:
                            # find the parameters in the device link
                            deviceParams = link["href"].split("?")[1].split("&")
                            # loop over the parameters
                            for param in deviceParams:
                                [field, value] = param.split("=")
                                # if this paramter is the object ID
                                if field == "object_id":
                                    # store the value
                                    deviceID = value
                                    break
                    # if this is not a device link, skip it
                    # non-device links do not have a "strong" attribute
                    except AttributeError:
                        pass
    return deviceID

def getDeviceSwVersion(session, url, deviceID):
    version = ""
    # query the RackTables object
    response = session.get(url+"index.php?page=object&object_id="+deviceID)
    # format the response
    output = soup(response.text, "html.parser")
    # find all sections of the results
    sections = output.body.div.find("div", {"class": "pagebar"}).findAll("div", {"class": "portlet"})
    # loop over each section to find the summary section
    for section in sections:
        if section.h2.text == "summary":
            # get all rows of device information
            device_info = section.findAll("tr")
            # loop over device information
            for info in device_info:
                try:
                    # if this is the SW version row
                    if info.th.text == "SW version:":
                        # store the SW version
                        version = info.td.text
                except AttributeError:
                    pass
            break
    return version

def getDeviceSN(session, url, deviceID):
    sn = ""
    # query the RackTables object
    response = session.get(url+"index.php?page=object&object_id="+deviceID)
    # format the response
    output = soup(response.text, "html.parser")
    # find all sections of the results
    sections = output.body.div.find("div", {"class": "pagebar"}).findAll("div", {"class": "portlet"})
    # loop over each section to find the summary section
    for section in sections:
        if section.h2.text == "summary":
            # get all rows of device information
            device_info = section.findAll("tr")
            # loop over device information
            for info in device_info:
                try:
                    # if this is the SN row
                    if "OEM S/N" in info.th.text:
                        # store the SW version
                        sn = info.td.text
                except AttributeError:
                    pass
            break
    return sn

def getDeviceLocation(session, url, deviceID):
    location = "None"
    # query the RackTables object
    response = session.get(url+"index.php?page=object&object_id="+deviceID)
    # format the response
    output = soup(response.text, "html.parser")
    # find the rackspace section of the results
    rackspace = output.body.div.find("div", {"class": "pagebar"}).find("td", {"class": "pcright"})
    # get the rack location
    try:
        rackInfo = rackspace.findAll("a")
        if len(rackInfo) > 0:
            # if this pod has multiple racks
            if rackInfo[1].img:
                location = rackInfo[0].text.replace("-",".") + "." + rackInfo[2].text
            # if this pod has only one rack
            else:
                location = rackInfo[0].text.replace("-",".") + "." + rackInfo[1].text
            # get all RUs in the rack
            rack_rows = output.find("table", {"class": "rack"}).findAll("tr")
            # loop over all RUs in the rack
            ru = ""
            for row in rack_rows:
                try:
                    # if the row object is highlighted
                    if " ".join(row.td["class"]) == "atom state_Th":
                        # find the starting RU location and the object height
                        startRU = row.th.text
                        spanRU = row.td["rowspan"]
                        # calculate the full RU location
                        ru = startRU + "-" + str(int(startRU)-int(spanRU)+1)
                except TypeError:
                    pass
            # if the RU location was found, add it to the string
            if len(ru) > 0:
                location += ":RU" + ru
    except AttributeError:
        pass
    return location

def getDeviceIPs(session, url, deviceID):
    # initialize IP arrays
    ipv4 = []
    ipv6 = []
    # query the RackTables object
    response = session.get(url+"index.php?page=object&object_id="+deviceID)
    # format the response
    output = soup(response.text, "html.parser")
    # find all sections of the results
    sections = output.body.div.find("div", {"class": "pagebar"}).table.findAll("div", {"class": "portlet"})
    # loop over each section to find the IP addresses section
    for section in sections:
        if section.h2.text == "IP addresses":
            # find all table rows in the section
#      interface_rows = section.table.findAll("tr", {"class": "trbusy"}) + section.table.findAll("tr", {"class": "trerror"})
            interface_rows = section.table.findAll("tr")
            # loop over each row in the section
            ipCount = 0
            for row in interface_rows:
                if row.get("class"):
                    if row["class"][0] == "trbusy" or row["class"][0] == "trerror":
                        # initialize the location of the assigned IP and network info
                        ipCol = 1
                        networkCol = 2
                        # find all fields for the row
                        cols = row.findAll("td")
                        # if the interface has multiple IPs assigned
                        if cols[0].get("rowspan"):
                            # record the number of IPs on the interface
                            ipCount = int(cols[0].get("rowspan")) - 1
                            # get the interface name and IP assigned
                            interface = cols[0].text
                        # otherwise
                        else:
                            # if this interface has only one IP
                            if ipCount == 0:
                                # get the interface name and IP assigned
                                interface = cols[0].text
                            # if this row is one of several under the interface
                            else:
                                # shift the locations to the left by 1
                                ipCol -= 1
                                networkCol -=1
                                # decrease the count of IPs remaining to collect
                                ipCount -= 1
                        # get the IP assigned to the interface
                        ip = cols[ipCol].a.text
                        network = cols[networkCol]#.table
                        # get the network subnet/prefix
                        subnet = network.a.text
                        # get the network description
                        try:
                            description = network.strong.text
                        # if the network has no description
                        except AttributeError:
                            description = "None"
                        # create IP JSON
                        ipInfo = {"Interface": interface, "Assigned": ip, "Network": subnet, "Description": description}
                        # add the info to the appropriate array
                        if ":" in ip:
                            ipv6.append(ipInfo)
                        else:
                            ipv4.append(ipInfo)
            break
    return [ipv4, ipv6]

def linkIP(session, url, deviceID, interface, ip):
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=object&tab=ip&op=add
    ## payload:
    #### object_id = 1279
    #### bond_name = Loopback0
    #### ip = 24.28.208.95
    #### bond_type = virtual
    ###### virtal is for Loopback
    ###### router is for Router
    ###### point2point is for Point-to-Point
    ###### regular is for connected
    ###### shared is for Shared
    linkTypes = [["virtual", ["loopback",
                                                        "mgmteth",
                                                        "video",
                                                        "led"
                                                      ]
                              ],
                              ["router", ["vlan",
                                                        "bvi",
                                                        "bundle-ether",
                                                        "cable-mac",
                                                        "ip-bundle",
                                                        "bundle",
                                                        "pd",
                                                        "virtualportgroup"
                                                    ]
                              ],
                              ["point2point", ["ethernet",
                                                        "port-channel",
                                                        "tengige",
                                                        "tengigabitethernet",
                                                        "twentyfivegige",
                                                        "xgige",
                                                        "gigabitethernet",
                                                        "hundredgige"
                                                    ]
                              ],
                              ["regular", ["eth",
                                                        "fastethernet"
                                                    ]
                              ]
                            ]
    # make the interface name lowercase
    interface_lower = interface.lower()
    foundType = False
    # loop over the link types
    for linkType in linkTypes:
        bond = linkType[0]
        # loop over each
        for name in linkType[1]:
            # if this interface type is found in the link types array
            if name in interface_lower:
                foundType = True
                break
        if foundType:
            break

    # create data JSON to send
    payload = {"object_id": deviceID, "bond_name": interface, "ip": ip, "bond_type": bond}
    # send data to add the network
    response = session.post(url+"index.php?module=redirect&page=object&tab=ip&op=add", data=payload)
    # format the response
    output = soup(response.text, "html.parser")
    # get all messages in the response
    message_containers = output.body.div.findAll("div", {"class": "msgbar"})
    # collect the return messages
    messages = []
    for message_container in message_containers:
        messages.append(message_container.div.text)
        # if a success message was printed
#    if "added a record successfully" in message_container.div.text:
  #     success = True
    #return success
    return messages

def deleteLink(session, url, deviceID, assigned):
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=object&tab=ip&op=del&ip=24.28.208.95&object_id=1279
## payload:
#### ip = 24.28.208.95
#### object_id = 1279
    # send the delete request
    response = session.post(f"{url}index.php?module=redirect&page=object&tab=ip&op=del&ip={assigned}&object_id={deviceID}")
    # format the response
    output = soup(response.text, "html.parser")
    # get all messages in the response
    message_containers = output.body.div.findAll("div", {"class": "msgbar"})
    # collect the return messages
    messages = []
    for message_container in message_containers:
        messages.append(message_container.div.text)
    return messages

def getDevicePorts(session, url, deviceID):
    ports = []
    # query the RackTables object
    response = session.get(url+"index.php?page=object&object_id="+deviceID)
    # format the response
    output = soup(response.text, "html.parser")
    # find all sections of the results
    sections = output.body.div.find("div", {"class": "pagebar"}).table.findAll("div", {"class": "portlet"})
    # loop over each section to find the IP addresses section
    for section in sections:
        # if this is the ports section
        if section.h2.text == "ports and links":
            # find all port rows
            port_rows = section.table.findAll("tr")
            # loop over all port rows
            for row in port_rows[1:]:
                # collect all info for the port
                cols = row.findAll("td")
                portID = cols[0].a["name"].split("-")[1]
                port = cols[0].a.text
                portType = cols[2].text
                mac = cols[3].tt.text
                link = cols[4]
                try:
                    # if port has a Cable ID, collect it
                    cableID = cols[6].span.text
                except AttributeError:
                    cableID = ""
                try:
                    # if a device is linked to the port, get device name
                    objectName = link.a.text
                except AttributeError:
                    objectName = ""
                try:
                    # if a device is linked to the port, get device ID and port ID
                    objectLink = link.a["href"].split("?")[1].split("&")
                    objectID = ""
                    objectPortID = ""
                    for info in objectLink:
                        [field, value] = info.split("=")
                        if field == "object_id":
                            objectID = value
                        elif field == "hl_port_id":
                            objectPortID = value
                except TypeError:
                    objectID = ""
                    objectPortID = ""
                objectPort = cols[5].span.text
                # collect linked object info
                linkedObject = {"Hostname": objectName, "Port": objectPort, "ID": objectID, "Port-ID": objectPortID}
                # collect full port info
                ports.append({"Port": port, "Port-ID": portID, "MAC": mac, "Type": portType, "Link": linkedObject, "Cable-ID": cableID})
            break
    return ports

def updateDevicePort(session, url, objectID, portID, portName, portTypeKey, mac, cableID, label):
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=object&tab=ports&op=editPort
    ## payload:
    #### port_id = 8350
    #### object_id = 1279
    #### name = Te1/3
    #### label = ""
    #### port_type_id = 9-36
    #### l2address = ""
    #### reservation_comment = ""
    #### cable = BF434

    # create data JSON to send
    payload = {"object_id": objectID, "port_id": portID, "name": portName, "port_type_id": portTypeKey,\
                          "l2address": mac, "cable": cableID, "label": label, "reservation_comment": ""}
    # send data to update the port
    response = session.post(url+"index.php?module=redirect&page=object&tab=ports&op=editPort", data=payload)
    # format the response
    output = soup(response.text, "html.parser")
    # get all messages in the response
    messages = output.body.div.findAll("div", {"class": "msgbar"})
    # determine if the update was successful
    success = False
    for message in messages:
        # if a success message was printed
        if "updated record" in message.div.text and "successfully" in message.div.text:
            success = True
    return success

# adding a new port
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=object&tab=ports&op=addBulkPorts
## payload:
#### object_id = 1279
#### port_name = TEMP
#### port_label = Next
#### port_type_id = 1084
#### port_numbering_start = 1
#### port_numbering_count = 1

# deleting a port
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=object&tab=ports&op=delPort&port_id=25803&object_id=1279
## payload:
#### port_id = 25803
#### object_id = 1279

#######################################################################################
################################# Non-device specific #################################
#######################################################################################
def getTags(session, url):
    tags = []
    # query RackTables for all tags
    response = session.get(url+"index.php?page=tagtree")
    # format the response
    output = soup(response.text, "html.parser")
    # find all rows of tags of the response
    tag_rows = output.body.div.find("div", {"class": "pagebar"}).center.table.findAll("span")
    # loop over each tag
    for row in tag_rows:
        name = ""
        tagID = ""
        # get the name of the tag
        name = row.text.split(" ")[0]
        # the ID of the tag is in the element title
        tagID_string = row["title"].split(",")[0].split(" ")
        # grab only the number from the title
        tagID = tagID_string[len(tagID_string)-1]
        # add the tag to the final array
        tags.append({"Name": name, "ID": tagID})
    return tags

def tagName2Id(tags, names):
    tagIDs = []
    # convert the array of tag names to tag ID values
    for name in names:
        for tag in tags:
            if name == tag["Name"]:
                tagIDs.append(tag["ID"])
    return tagIDs

def tagId2Name(tags, tagIDs):
    names = []
    # convert the arary of tag ID values to tag names
    for tagID in tagIDs:
        for tag in tags:
            if tagID == tag["ID"]:
                names.append(tag["Name"])
    return names

def getPorts(session, url):
    ports = []
    # query RackTables for the port types
    response = session.get(url+"index.php?page=portifcompat")
    # format the response
    output = soup(response.text, "html.parser")
    # find table of port types
    portTable = output.div.find("div", {"class": "pagebar"}).table
    # get each port row
    portRows = portTable.findAll("tr", {"class": "row_even"}) + portTable.findAll("tr", {"class": "row_odd"})
    # loop over all port rows
    for row in portRows:
        # find each column in the row
        col = row.findAll("td")
        # get info for each port type
        name = col[1].text + "/" + col[3].text
        key = col[0].text + "-" + col[2].text
        # add the port type to the final array
        ports.append({"Key": key, "Name": name})
    return ports

def portName2Key(ports, name):
    key = ""
    # convert port type to port key
    for port in ports:
        if port["Name"] == name:
            key = port["Key"]
            break
    # if no name was matched
    if len(key) == 0:
        # look for less specific match
        name = name.split("/")[len(name.split("/"))-1]
        for port in ports:
            if name == port["Name"].split("/")[len(port["Name"].split("/"))-1]:
                key = port["Key"]
                break
    return key

def portKey2Name(ports, key):
    name = ""
    # convert port key to port type
    for port in ports:
        if port["Key"] == key:
            name = port["Name"]
            break
    return name

#######################################################################################
################################### Network specific ##################################
#######################################################################################
def getNetworkID(session, url, ip):
    networkID = -1
    # query RackTables for the ip
    response = session.get(url+"index.php?page=search&last_page=ipv4net&last_tab=default&q="+ip)
    # format the response
    output = soup(response.text, "html.parser")
    # determine if the responded page is the network or a device
    networkPage = False
    # find the current page's directory
    dirs = output.body.div.find("div", {"class": "menubar"}).findAll("a")
    # if this page is a network page
    if dirs[1].text == "IPv4 space" or dirs[1].text == "IPv6 space":
        # get the link of the network
        networkLink = dirs[2]["href"].split("?")[1].split("&")
        for info in networkLink:
            # obtain the ID from the link of the network
            [field, value] = info.split("=")
            if field == "id":
                networkID = value
                break
    # otherwise, the IP searched must be assigned to a device
    else:
        # find all sections of the results
        if output.body.div.find("div", {"class": "pagebar"}).table:
            sections = output.body.div.find("div", {"class": "pagebar"}).table.findAll("div", {"class": "portlet"})
            # loop over each section to find the IP addresses section
            for section in sections:
                if section.h2.text == "IP addresses":
                    # find all table rows in the section
                    interface_rows = section.table.findAll("tr", {"class": "trbusy"}) + section.table.findAll("tr", {"class": "trerror"})
                    # loop over each row in the section
                    ipCount = 0
                    for row in interface_rows:
                        # initialize the location of the assigned IP and network info
                        ipCol = 1
                        networkCol = 2
                        # find all fields for the row
                        cols = row.findAll("td")
                        # if the interface has multiple IPs assigned
                        if cols[0].get("rowspan"):
                            # record the number of IPs on the interface
                            ipCount = int(cols[0].get("rowspan")) - 1
                            # get the interface name and IP assigned
                            interface = cols[0].text
                        # otherwise
                        else:
                            # if this interface has only one IP
                            if ipCount == 0:
                                # get the interface name and IP assigned
                                interface = cols[0].text
                            # if this row is one of several under the interface
                            else:
                                # shift the locations to the left by 1
                                ipCol -= 1
                                networkCol -=1
                                # decrease the count of IPs remaining to collect
                                ipCount -= 1
                        # get the IP assigned to the interface
                        deviceIP = cols[ipCol].a.text
                        if ip == deviceIP:
                            # get the network subnet/prefix link
                            networkLink = cols[networkCol].table.a["href"].split("?")[1].split("&")
                            for info in networkLink:
                                # obtain the ID from the link of the network
                              [field, value] = info.split("=")
                              if field == "id":
                                  networkID = value
                                  break
    return networkID

def networkInfo(session, url, ip):
    name = ""
    network = ""
    tags = []
    router = ""
    interface = ""
    gateway = ""
    # ensure no prefix size is specified
    ip = ip.split("/")[0]
    # get network ID
    networkID = getNetworkID(session, url, ip)
    if networkID != -1:
        # determine IP type
        if ":" in ip:
            ipType = "6"
        else:
            ipType = "4"
        # query the RackTables network
        response = session.get(url+"index.php?page=ipv"+ipType+"net&tab=default&id="+networkID)
        # format the response
        output = soup(response.text, "html.parser")
        # find all sections of the results
        section = output.body.div.find("div", {"class": "pagebar"}).table
        # get network ID and network name
        network = section.h1.text
        name = section.h2.text
        # get table of network info
        table_rows = output.find("div", {"class": "pagebar"}).table.findAll("tr")
        # loop over rows of info
        for row in table_rows:
            # if this is the Explicit tags row
            try:
                if "Explicit" in row.th.text:
                    # collect tags
                    explicitTags = row.findAll("a")
                    for tag in explicitTags:
                        tags.append(tag.text)
                    break
                else:
                    # get network router info
                    if "Routed by:" in row.th.text:
                        router = row.table.tr.strong.text
                        [gateway, interface] = row.table.tr.td.text.split("@")
            # if this row has no router info
            except AttributeError:
                pass
        # if the router has not been found
        if len(router) == 0:
            # find all IPs with an allocation
            allocations = output.find("td", {"class": "pcright"}).div.table.findAll("tr", {"class": "trbusy"})
            for allocation in allocations:
                # find each column in the allocation
                col = allocation.findAll("td")
                try:
                    # if this is the subnet/prefix router's IP
                    if col[3].span["title"] == "Router":
                        gateway = col[0].a.text
                        [interface, router] = col[3].a.text.split("@")
                except TypeError:
                    pass
        # collect full network info
        networkInfo = {"ID": networkID, "Network": network, "Name": name, "Tags": tags, "Router": router, "Interface": interface, "Gateway": gateway}
    else:
        networkInfo = {"ID": networkID}
    return networkInfo

def addNetwork(session, url, network, name, tags, reserve_ID_broadcast):
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=ipv4space&tab=newrange&op=add
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=ipv6space&tab=newrange&op=add
    ## payload:
    #### range = 1.0.0.0/24 or 1::/64
    #### vlan_ck_ = ""
    #### vlan_ck = ""
    #### name = TEMP
    #### taglist[] = 105
    #### is_connected = on

    # determine if the network ID and network broadcast should be reserved
    if reserve_ID_broadcast:
        connected = "on"
    else:
        connected = "off"
    # translate tags to IDs
    rt_tags = []
    if len(tags) > 0:
        all_tags = getTags(session, url)
        for tag in tags:
            for rt_tag in all_tags:
                if tag == rt_tag["Name"] or tag == rt_tag["ID"]:
                    rt_tags.append(rt_tag["ID"])
                    break
    # if this is an IPv6 network
    if ":" in network:
        url_extension = "index.php?module=redirect&page=ipv6space&tab=newrange&op=add"
    # if this is an IPv4 network
    else:
        url_extension = "index.php?module=redirect&page=ipv4space&tab=newrange&op=add"

    # create data JSON to send
    payload = {"range": network, "vlan_ck_": "", "vlan_ck": "", "name": name,\
                          "taglist[]": rt_tags, "is_connected": connected}
    # send data to add the network
    response = session.post(url+url_extension, data=payload)
    # format the response
    output = soup(response.text, "html.parser")
    # get all messages in the response
    message_containers = output.body.div.findAll("div", {"class": "msgbar"})

    # determine if the update was successful
    success = False
  # for message in messages:
        # if a success message was printed
    #  if "IP network" in message.div.text and "has been created" in message.div.text:
      #   success = True
    #return success
    # collect the return messages
    messages = []
    for message_container in message_containers:
        messages.append(message_container.div.text)
        # if a success message was printed
        if "IP network" in message_container.div.text and "has been created" in message_container.div.text:
            success = True
    return [messages, success]

def updateNetwork(session, url, network, networkID, name, tags):
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=ipv4net&tab=properties&op=editRange
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=ipv6net&tab=properties&op=editRange
    ## payload:
    #### id = 2374
    #### name = TEMP2
    #### taglist[] = [92, 116]
    #### comment = ""
    # translate tags to IDs
    rt_tags = []
    if len(tags) > 0:
        all_tags = getTags(session, url)
        for tag in tags:
            for rt_tag in all_tags:
                if tag == rt_tag["Name"] or tag == rt_tag["ID"]:
                    rt_tags.append(rt_tag["ID"])
                    break
    # if this is an IPv6 network
    if ":" in network:
        url_extension = "index.php?module=redirect&page=ipv6net&tab=properties&op=editRange"
    # if this is an IPv4 network
    else:
        url_extension = "index.php?module=redirect&page=ipv4net&tab=properties&op=editRange"
    # create data JSON to send
    payload = {"id": networkID, "name": name, "taglist[]": rt_tags, "comment": "This network is maintained via less-tools."}
    # send data to update the network
    response = session.post(url+url_extension, data=payload)
    # format the response
    output = soup(response.text, "html.parser")
    # get all messages in the response
    message_containers = output.body.div.findAll("div", {"class": "msgbar"})
    # determine if the update was successful
#  success = False
  # for message in messages:
        # if a success message was printed
    #  if "updated record" in message.div.text and "successfully" in message.div.text:
      #   success = True
    #return success
    # collect the return messages
    messages = []
    for message_container in message_containers:
        messages.append(message_container.div.text)
    return messages

def deleteNetwork(session, url, network):
# delete a network
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=ipv4net&tab=properties&op=del&id=4416
## http://vidadev.charterlab.com/racktables/index.php?module=redirect&page=ipv6net&tab=properties&op=del&id=2315
    ## payload:
    #### module = redirect
    #### page = ipv4net
    #### tab = properties
    #### op = del
    #### id = 4416
    # if this is an IPv6 network
    if ":" in network:
        ipType = "6"
    # if this is an IPv4 network
    else:
        ipType = "4"
    # get the network ID
    networkData = networkInfo(session, url, network.split("/")[0])
    networkID = networkData["ID"]
    # if this is the correct network
    if networkData["ID"] != -1:
        if networkData['Network'] == network:
            # send the request to delete
            response = session.get(f"{url}index.php?module=redirect&page=ipv{ipType}net&tab=properties&op=del&id={networkID}")
            # format the response
            output = soup(response.text, "html.parser")
            # get all messages in the response
            message_containers = output.body.div.findAll("div", {"class": "msgbar"})
            # collect the return messages
            messages = []
            for message_container in message_containers:
                messages.append(message_container.div.text)
        else:
            messages = [f"Failed to delete {network}. Found mismatched network {networkData['Network']}."]
    else:
        messages = [f"Failed to delete {network}. Network not found."]
    return messages

