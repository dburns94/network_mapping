#!/usr/bin/python3.6

def getHostname(json):
    try:
        return json["hostname"]
    except:
        return "0"

def getHost(json):
    try:
        return json["Host"]
    except:
        return "0"

def getModel(json):
    try:
        return json["model"]
    except:
        return "0"

def getNumber(json):
    try:
        return json['number']
    except KeyError:
        return 0

def getInterface(json):
    try:
        return format_numbers(json['Interface'], 2)
    except:
        return "0"

def format_numbers(string, digits):
    # declare string of valid numbers
    numbers = "1234567890"
    # initialize strings
    new_string = ""
    current_num = ""
    # for each character in the string
    for char in string:
        # if this character is a number
        if char in numbers:
            # add it to te number string
            current_num += char
        # if this character is not a string
        else:
            # if there are characters in the number string
            if len(current_num) > 0:
                # format the number string with the specified number of digits
                # then add the number string to the new string
                new_string += current_num.zfill(digits)
                # clear the number string
                current_num = ""
            # add the character to the new string
            new_string += char
    # if the string ended in numbers
    if len(current_num) > 0:
        # format the number string with the specified number of digits
        # then add the number string to the new string
        new_string += current_num.zfill(digits)
    return new_string

def expand_ipv4(address):
    # seperate network and subnet
    ip = address.split("/")
    # seperate octets
    octets = ip[0].split(".")
    # pad octets with leading zeros
    for i in range(len(octets)):
        octets[i] = octets[i].zfill(3)
    # join octets
    address = ".".join(octets)
    # if subnet was provided
    if len(ip) > 1:
        # pad subnet with leading zeros
        ip[1] = ip[1].zfill(2)
        # add subnet to address
        address += "/"+ip[1]
    return address

def expand_ipv6(address):
# expands an IPv6 address to contain no '::'
    # seperate ip and prefix
    ip = address.split("/")
    # split on the longest series of zeros
    pieces = ip[0].split("::")
    # if there are two pieces
    if len(pieces) == 2:
        # get each hextet
        first_hextets = pieces[0].split(":")
        sec_hextets = pieces[1].split(":")
        # ensure there are no blank hextets
        for i in range(len(first_hextets)):
            if len(first_hextets[i]) == 0:
                first_hextets[i] = "0"
        for i in range(len(sec_hextets)):
            if len(sec_hextets[i]) == 0:
                sec_hextets[i] = "0"
        # add the proper amound of hextets to the first piece
        for i in range(8-len(first_hextets)-len(sec_hextets)):
            first_hextets.append("0")
        # combine the two hextets
        hextets = first_hextets + sec_hextets
        # combine all hextets into an address
        address = ":".join(hextets)
    # pad hextets with leading zeros
    hextets = ip[0].split(":")
    for i in range(len(hextets)):
        hextets[i] = hextets[i].zfill(4)
    # combine all hextets into an address
    address = ":".join(hextets)
    # if a prefix was given
    if len(ip) > 1:
        # pad prefix with leading zeros
        ip[1] = ip[1].zfill(2)
        # add prefix to the address
        address += "/" + ip[1]
    return address

