#!/usr/bin/python3.6

import re

def determine_type(value):
    # determine value type
    if valid_mac(value):
        valueType = "MAC"
    elif valid_ipv4(value):
        valueType = "IPv4"
    elif valid_ipv6(value):
        valueType = "IPv6"
    else:
        valueType = None
    return valueType

def int_to_hex(num):
    return hex(num).split("x")[1]

def twos_compliment_reverse(dec, bits):
# calculates a value from a two's compliment
    binary = bin(0-dec-1).split('b')[-1].zfill(bits)
    newBin = "0b"
    for i in binary:
        if i == '0':
            newBin += '1'
        else:
            newBin += '0'
    return int(newBin, 2)

def multicast_conv(address):
# converts a layer 3 multicast address into a layer 2 multicast address
    layerTwo = ""
    if valid_ipv4(address):
        # layer 2 multicast addresses always being with "0100.5e"
        layerTwo = "0100.5e"
        pieces = address.split('.')
        # add the second octet of the IP to the MAC address
        layerTwo += str(hex(int(pieces[1])).split('x')[-1]).zfill(2)
        layerTwo += '.'
        # add the third octet of the IP to the MAC address
        layerTwo += str(hex(int(pieces[2])).split('x')[-1]).zfill(2)
        # add the fourth/last octet of the IP to the MAC address
        layerTwo += str(hex(int(pieces[3])).split('x')[-1]).zfill(2)
    return layerTwo

def valid_mac(string):
# returns whether a string is a valid mac-address or not
    # pattern = re.compile(r"(([\da-f]{2}[:\-.]){5}[\da-f]{2}|([\da-f]{4}[:\-.]){2}[\da-f]{4}|[\da-f]{12})", re.I)
    if string is None:
        return False
    # remove all characters that are not a hex value
    mac = ""
    for char in string.lower():
        if char not in '.:- ':
            mac += char
    # MAC addresses must be 12 nibbles
    if len(mac) != 12:
        return False
    # ensure each value is a hex value
    try:
        # each nibble must be decimal 0-15
        for i in mac:
            if int(i,16) > 15:
                return False
    # if the digit is not a hex value
    except ValueError:
        return False
    return True

def format_mac(mac, char=':', case='lower'):
    # remove all invalid characters
    validChars = "1234567890abcdef"
    if case.lower() == "lower":
        mac = mac.lower()
    else:
        mac = mac.upper()
        validChars = validChars.upper()
    newMAC = ""
    for i in mac:
        if i in validChars:
            newMAC += i
    if char == '.':
        # add periods every 4 characters
        mac = ""
        for i in range(len(newMAC)):
            mac += newMAC[i]
            if i != 0 and (i+1) % 4 == 0:
                mac += '.'
    elif char == ':':
        # add colons every 2 characters
        mac = ""
        for i in range(len(newMAC)):
            mac += newMAC[i]
            if i != 0 and (i+1) % 2 == 0:
                mac += ':'
    return mac[:-1]

def valid_ipv4(address):
# validates an IPv4 address
    # pattern = re.compile(r"(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?")
    valid = True
    # seperate ip and prefix
    ip = address.split("/")
    # get each byte/octet
    octets = ip[0].split(".")
    # there must be 4 octets, for a total of 32 bits
    if len(octets) != 4:
        valid = False
    else:
        # ensure each octet is a value 0-255
        try:
            for octet in octets:
                value = int(octet)
                if value < 0 or value > 255:
                    valid = False
                    break
        # if the octet is not a number
        except ValueError:
            valid = False
        # if this is a valid IP and a prefix was provided
        if valid and len(ip) > 1:
            # ensure the prefix is a value 0-32
            try:
                value = int(ip[1])
                if value < 0 or value > 32:
                    valid = False
            # if the prefix was not a number
            except ValueError:
                valid = False
    return valid

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

def condense_ipv4(address):
# formats an IPv4 address into dense format (reverse of expand_ipv4)
    ip = address.split("/")
    # seperate octets
    octets = ip[0].split(".")
    # remove leading zeros from octets
    for i in range(len(octets)):
        octets[i] = str(int(octets[i]))
    # join octets
    address = ".".join(octets)
    # if subnet was provided
    if len(ip) > 1:
        # remove leading zeros from subnet
        ip[1] = str(int(ip[1]))
        # add subnet to address
        address += "/"+ip[1]
    return address

def ipv4_to_dec(address):
# converts an IPv4 address to decimal
    decIP = 0
    # seperate the IP from prefix
    ip = address.split("/")
    # get each byte/octet
    octets = ip[0].split(".")
    # add each octets value to decIP
    for i in range(len(octets)):
        value = int(octets[i])
        decIP += (value<<(24-8*i))
    return decIP

def dec_to_ipv4(decIP):
    # converts a decimal value to IPv4
    octets = []
    # for four octets
    for i in range(4):
        # calculate the value of the octet
        value = decIP>>(24-8*i)&(2**8-1)
        # add the value to the array of bytes/octets
        octets.append(str(value))
    return ".".join(octets)

def nth_ipv4(address, N, dec=False):
# gets the Nth IPv4 address in the subnet
    # seperate the IP from prefix
    ip = address.split("/")
    # calculate the decimal value of the IP
    decIP = ipv4_to_dec(ip[0])
    # calculate the number of host bits
    mask = 32-int(ip[1])
    # calculate the network ID
    decIP = (decIP>>mask)<<mask
    # if user wants the last IP (the broadcast value)
    if (str(N).lower())=="last":
        # OR the decimal IP with the host bits
        decIP |= (2**mask-1)
    # otherwise, add the number of IPs desired
    else:
        decIP += int(N)
    # if user want's a decimal value
    if dec:
        return decIP
    # translate the decimal IP back to regular format
    address = dec_to_ipv4(decIP)
    # add the prefix back to the IP
    address += "/"+ip[1]
    return address

def in_range_ipv4(address, subnet):
# determines if an IPv4 address is inside a specific range
    # seperate the IP from prefix
    ip = subnet.split("/")
    # use the same prefix for both
    address = address.split("/")[0] + "/" + ip[1]
    # calculate the network ID for both networks
    networkOne = nth_ipv4(address, 0)
    networkTwo = nth_ipv4(subnet,0)
    # if the network IDs are the same
    if networkOne == networkTwo:
        match = True
    else:
        match = False
    return match

def mask_to_prefix(mask):
# converts an IPv4 subnet mask to an IPv4 prefix (i.e. 255.255.255.0 to /24)
    prefix = 32
    # calculate the decimal value of the IP
    decIP = ipv4_to_dec(mask)
    # loop over each bit, finding the last 1
    foundZero = False
    for i in range(1,33):
        # calculate the binary value of the bit
        value = (decIP>>(32-i))&1
        # if the value is a binary 1
        if value:
            # if a 0 has already been found
            if foundZero:
                # this is not a valid subnet mask
                prefix = -1
                break
        # if a binary value of 0 was found
        else:
            # if this is the first 0 found
            if not(foundZero):
                # set the prefix length
                prefix = i - 1
                foundZero = True
    return prefix

def prefix_to_mask(prefix):
# converts an IPv4 prefix to an IPv4 subnet mask (i.e. /24 to 255.255.255.0)
    mask = dec_to_ipv4(2**32-2**(32-int(prefix)))
    return mask

def wildcard_to_prefix(wildcard):
# converts an IPv4 wildcard mask to and IPv4 prefix (i.e. 0.0.0.255 to /24)
    prefix = 32
    # calculate the decimal value of the IP
    decIP = ipv4_to_dec(wildcard)
    # loop over each bit, finding the last 0
    foundOne = False
    for i in range(1,33):
        # calculate the binary value of the bit
        value = (decIP>>(32-i))&1
        # if the value is a 1
        if value:
            # if this is the first 1 found
            if not(foundOne):
                # set the prefix length
                prefix = i - 1
                foundOne = True
        # if a binary value of 0 was found
        else:
            # if a 1 has already been found
            if foundOne:
                # this is not a valid wildcard mask
                prefix = -1
                break
    return prefix

def prefix_to_wildcard(mask):
# converts an IPv4 prefix to an IPv4 wildcard mask (i.e. /24 to 0.0.0.255)
    wildcard = dec_to_ipv4(2**(32-int(mask))-1)
    return wildcard

def first2Hextets(address):
# returns the first 16 bits and second 16 bits of an IPv6 address
    decIP = 0
    # exapnd the IPv6 address to contain no "::"
    address = expand_ipv6(address)
    # seperate ip and prefix
    ip = address.split("/")
    # get each hextet
    hextets = ip[0].split(":")
    # calculate hextets value's in decimal
    first_hextet = int(hextets[0], 16)
    second_hextet = int(hextets[1], 16)
    return first_hextet, second_hextet

def first_three(address):
# returns the first, second, and third 16 bits (48-bits total)
    decIP = 0
    # exapnd the IPv6 address to contain no "::"
    address = expand_ipv6(address)
    # seperate ip and prefix
    ip = address.split("/")
    # get each hextet
    hextets = ip[0].split(":")
    # calculate hextets value's in decimal
    first_hextet = int(hextets[0], 16)
    second_hextet = int(hextets[1], 16)
    third_hextet = int(hextets[2], 16)
    return first_hextet, second_hextet, third_hextet

def valid_ipv6(address):
# validates an IPv6 address
    # pattern = re.compile(r"(([\da-f]{1,4}:){7}[\da-f]{1,4}|([\da-f]{1,4})?::([\da-f]{1,4})?|(([\da-f]{1,4}:)*[\da-f]{1,4})?::(([\da-f]{1,4}:)*[\da-f]{1,4})?)(/\d{1,3})?", re.I)
    valid = True
    # seperate ip and prefix
    ip = address.split("/")
    # split on the longest series of zeros
    pieces = ip[0].split("::")
    # ensure there is not more than two "::"
    if len(pieces) > 2:
        valid = False
    # if there is only one piece (i.e. no "::")
    elif len(pieces) == 1:
        # get each hextet
        hextets = pieces[0].split(":")
        # ensure there are 8 hextets
        if len(hextets) != 8:
            valid = False
        else:
            # ensure each hextet is a value 0-65535
            try:
                for hextet in hextets:
                    value = int(hextet, 16)
                    if value < 0 or value > 65535:
                        valid = False
                        break
            # if the hextet is not a number
            except ValueError:
                valid = False
    # if there are two pieces
    else:
        # get each hextet
        first_hextets = pieces[0].split(":")
        sec_hextets = pieces[1].split(":")
        # ensure there are not more than 7 hextets combined
        if len(first_hextets) + len(sec_hextets) > 7:
            valid = False
        else:
            # ensure each hextet is a value 0-65535
            try:
                for hextet in first_hextets:
                    if len(hextet) > 0:
                        value = int(hextet, 16)
                        if value < 0 or value > 65535:
                            valid = False
                            break
                for hextet in sec_hextets:
                    if len(hextet) > 0:
                        value = int(hextet, 16)
                        if value < 0 or value > 65535:
                            valid = False
                            break
            # if the hextet is not a number
            except ValueError:
                valid = False
    # if this is a valid IP and a prefix was provided
    if valid and len(ip) > 1:
        # ensure the prefix is a value 0-128
        try:
            value = int(ip[1])
            if value < 0 or value > 128:
                valid = False
        # if the prefix was not a number
        except ValueError:
            valid = False
    return valid

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
        # add all padded zeros
        for i in range(len(hextets)):
            hextets[i] = hextets[i].zfill(4)
        # combine all hextets into an address
        address = ":".join(hextets)
        # if a prefix was given, add it to the address
        if len(ip) > 1:
            address += "/" + ip[1].zfill(3)
    return address

def condense_ipv6(address):
# formats an IPv6 address into dense format (reverse of expand_ipv6)
    # expand IP to ensure there are no miscalculations
    address = expand_ipv6(address)
    # seperate ip and prefix
    ip = address.split("/")
    # get each hextet
    hextets = ip[0].split(":")
    # find all sequential series of zeros
    foundZero = False
    start = -1
    posx = []
    for i in range(len(hextets)):
        # if this is a 0
        if int(hextets[i], 16) == 0:
            # start looking for end of series
            if not(foundZero):
                start = i
                foundZero = True
        # if this is not a 0 and previously it was a 0
        elif foundZero:
            # add this sequence to the array of series
            posx.append([start, i-1])
            # start the search for series of zeros over
            foundZero = False
    # if a starting position was found and the last hextet was a 0
    if start != -1 and int(hextets[i], 16) == 0:
        # add this sequence to the array of series
        posx.append([start, i])
    # find longest sequence
    max_posx = -1
    max_diff = 0
    for i in range(len(posx)):
        # if this series is longer than the previous
        if posx[i][1] - posx[i][0] >= max_diff:
            # store the results
            max_posx = i
            max_diff = posx[i][1] - posx[i][0]
    # if a series of zeros was found
    if max_diff > 0:
        # create new address string using "::" if needed
        address = ""
        for i in range(len(hextets)):
            # if this position is the start of the longest series of zeros
            if i == posx[max_posx][0]:
                # if this is the first hextet
                if i == 0:
                    address += "::"
                else:
                    address += ":"
            # if this position is part of the longest series of zeros
            elif i > posx[max_posx][0] and i <= posx[max_posx][1]:
                pass
            # if this position is not part of the logest series of zeros
            else:
                # add the hextet to the final address string
                #address += hextets[i] + ":"
                address += hex(int(hextets[i], 16)).split("x")[1] + ':'
        # if the string does not end in "::"
        if address[len(address)-2:] != "::":
            # remove the extra ":" from the end of the address string
            address = address[:-1]
        # if a prefix was given, add it to the address
        if len(ip)>1:
            address += "/"+str(int(ip[1]))
    return address

def ipv6_to_dec(address):
# converts an IPv6 address to decimal
    decIP = 0
    # exapnd the IPv6 address to contain no "::"
    address = expand_ipv6(address)
    # seperate the IP from prefix
    ip = address.split("/")
    # get each hextet
    hextets = ip[0].split(":")
    # add each hextets value to decIP
    for i in range(len(hextets)):
        value = int(hextets[i], 16)
        decIP += (value<<(112-16*i))
    return decIP

def dec_to_ipv6(decIP):
    # converts a decimal value to IPv6
    hextets = []
    # for eight hextets
    for i in range(8):
        # calculate the value of the hextet
        value = decIP>>(112-16*i)&(2**16-1)
        # add the value to the array of hextets
        hextets.append(hex(value).split('x')[-1])
    return condense_ipv6(":".join(hextets))

def nth_ipv6(address, N, dec=False):
# gets the Nth IPv6 address in the subnet
    # seperate the IP from prefix
    ip = address.split("/")
    # calculate the decimal value of the IP
    decIP = ipv6_to_dec(ip[0])
    # calculate the number of host bits
    mask = 128-int(ip[1])
    # calculate the network ID
    decIP = (decIP>>mask)<<mask
    # if user wants the last IP (the broadcast value)
    if (str(N).lower())=="last":
        # OR the decimal IP with the host bits
        decIP |= (2**mask-1)
    # otherwise, add the number of IPs desired
    else:
        decIP += int(N)
    # if user want's a decimal value
    if dec:
        return decIP
    # translate the decimal IP back to regular format
    address = dec_to_ipv6(decIP)
    # add the prefix back to the IP
    address += "/"+ip[1]
    return address

def in_range_ipv6(address, prefix):
# determines if an IPv6 address is inside a specific range
    # seperate the IP from prefix
    ip = prefix.split("/")
    # use the same prefix for both
    address = address.split("/")[0] + "/" + ip[1]
    # calculate the network ID for both networks
    networkOne = nth_ipv6(address, 0)
    networkTwo = nth_ipv6(prefix, 0)
    # if the network IDs are the same
    if networkOne == networkTwo:
        match = True
    else:
        match = False
    return match

class IP:
    def __init__(self, ip, netmask=None, wildcard=None, offset=None):
        ip = ip.lower()
        if netmask is not None:
            self.addr = f"{ip}/{mask_to_prefix(netmask)}"
        elif wildcard is not None:
            self.addr = f"{ip}/{wildcard_to_prefix(wildcard)}"
        else:
            self.addr = ip
        if offset is not None:
            self.addr = self.nth(offset)
    def __repr__(self):
        """ to be used as representation for developers """
        return f"{self.addr}/{self.prefix}"
    def __str__(self):
        """ returns 'address' """
        return f"{self.addr}/{self.prefix}"
    @property
    def addr(self):
        """ returns the address of the IP """
        return self.__addr
    @addr.setter
    def addr(self, ip):
        """ sets the value of addr and recalculates type and valid """
        self.__addr = ip.split('/')[0]
        self.type = None
        self.network = ip
        self.valid = None
    @property
    def network(self):
        """ returns the network of the IP """
        return self.__network
    @network.setter
    def network(self, value):
        """ sets the value of the network         """
        """ SHOULD NOT BE USED outside this class """
        pieces = value.split('/')
        if len(pieces) == 1:
            if self.type == 4:
                self.__network = f"{value}/32"
            else:
                self.__network = f"{value}/128"
        else:
            self.__network = value
        try:
            if self.type == 4:
                self.__network = nth_ipv4(self.__network, 0)
            else:
                self.__network = nth_ipv6(self.__network, 0)
        except:
            self.__network = None
    @property
    def type(self):
        """ returns the IP type (4 or 6) of the IP """
        return self.__type
    @type.setter
    def type(self, placeholder):
        """ sets the IP type """
        if ':' in self.addr:
            self.__type = 6
        else:
            self.__type = 4
    @property
    def valid(self):
        """ returns True if the IP is valid """
        return self.__valid
    @valid.setter
    def valid(self, placeholder):
        """ sets the value of valid to True if the IP is valid """
        if self.type == 4:
            self.__valid = valid_ipv4(self.addr) and 0 <= self.prefix <= 32
        else:
            self.__valid = valid_ipv6(self.addr) and 0 <= self.prefix <= 128
    @property
    def netID(self):
        """ returns the network ID of the IP """
        if self.valid:
            return self.network.split('/')[0]
    @property
    def prefix(self):
        """ returns the prefix of the IP """
        return int(self.network.split('/')[1])
    @property
    def dec(self):
        """ returns the decimal value of the IP address """
        if self.valid:
            if self.type == 4:
                return ipv4_to_dec(self.addr)
            else:
                return ipv6_to_dec(self.addr)
    @property
    def expand(self):
        """ returns an expanded form of the network """
        """ typically used for sorting              """
        if self.valid:
            if self.type == 4:
                return expand_ipv4(self.network)
            else:
                return expand_ipv6(self.network)
    @property
    def condense(self):
        """ returns a condensed form of the network """
        if self.valid:
            if self.type == 4:
                return condense_ipv4(self.network)
            else:
                return condense_ipv6(self.network)
    @property
    def offset(self):
        """ returns the offset of the IP from the network ID """
        if self.valid:
            if self.type == 4:
                return ipv4_to_dec(self.addr) - ipv4_to_dec(self.network)
            else:
                return ipv6_to_dec(self.addr) - ipv6_to_dec(self.network)
    @property
    def netmask(self):
        """ returns the network mask of the IPv4 network """
        if self.valid and self.type == 4:
            return prefix_to_mask(self.prefix)
    @property
    def wildcard(self):
        """ returns the wildcard mask of the IPv4 network """
        if self.valid and self.type == 4:
            return prefix_to_wildcard(self.prefix)
    @property
    def broadcast(self):
        """ returns the broadcast address of the IPv4 network """
        if self.valid and self.type == 4:
            return nth_ipv4(self.network, 'last').split('/')[0]
    @property
    def total(self):
        """ returns the total IPs in the network """
        if self.valid:
            if self.type == 4:
                max_size = 32
            else:
                max_size = 128
            return  2**(max_size-self.prefix)
    @property
    def first(self):
        """ returns the first IP in the network """
        if self.valid:
            return self.network.split('/')[0]
    @property
    def last(self):
        """ returns the last IP in the network """
        if self.valid:
            if self.type == 4:
                return  nth_ipv4(self.network, 'last').split('/')[0]
            else:
                return  nth_ipv6(self.network, 'last').split('/')[0]
    @property
    def first_three(self):
        """ returns the first three half-hextets (16-bits each) of an IPv6 address"""
        if self.valid and self.type == 6:
            return first_three(self.network)
    @property
    def link_local(self):
        """ returns True if the IP is a link-local IP """
        if self.valid and self.type == 6 and self.dec >> 118 == 1018:
            return True
        else:
            return False
    def next_ip(self, N=1):
        """ returns the Nth IP after the IP                       """
        """ returns None if the Nth address is not in the network """
        if self.valid:
            if N <= (self.total - self.offset - 1):
                if self.type == 4:
                    return  dec_to_ipv4(self.dec + N)
                else:
                    return  dec_to_ipv6(self.dec + N)
    def next_network(self, N=1):
        """ returns the next network (subnet/prefix) """
        if self.valid:
            if self.type == 4:
                return dec_to_ipv4((self.dec - self.offset) + (self.total * N)) + '/' + str(self.prefix)
            else:
                return dec_to_ipv6((self.dec - self.offset) + (self.total * N)) + '/' + str(self.prefix)
    def nth(self, N, dec=False):
        """ returns the Nth address in the network                """
        """ returns None if the Nth address is not in the network """
        if self.valid:
            if (type(N) is int and N <= self.total) or (type(N) is str and N.lower() == 'last'):
                if self.type == 4:
                    return nth_ipv4(self.network, N, dec=dec)
                else:
                    return nth_ipv6(self.network, N, dec=dec)
    def contains(self, network):
        """ returns True if the IP or network is part of this network """
        if self.valid:
            if not isinstance(network, IP):
                ip = IP(network)
            if ip.valid and self.type == ip.type:
                first = self.nth(0, dec=True)
                last = self.nth('last', dec=True)
                ip_first = ip.nth(0, dec=True)
                ip_last = ip.nth('last', dec=True)
                return first <= ip_first and ip_last <= last
        return False
    def within(self, network):
        """ returns True if this network is a part of the network """
        if self.valid:
            if not isinstance(network, IP):
                ip = IP(network)
            if ip.valid and self.type == ip.type:
                first = self.nth(0, dec=True)
                last = self.nth('last', dec=True)
                ip_first = ip.nth(0, dec=True)
                ip_last = ip.nth('last', dec=True)
                return ip_first <= first and last <= ip_last
        return False
    def networks(self, max_prefix=None):
        """ returns all networks that contain this network """
        """ max prefix is specified by 'max_prefix'        """
        networks = []
        if self.valid:
            prefix = self.prefix
            netID = self.netID
            if self.type == 4:
                if max_prefix is None:
                    max_prefix = 8
                while prefix >= max_prefix:
                    network = nth_ipv4(f"{netID}/{prefix}", 0)
                    networks.append(network)
                    prefix -= 1
            else:
                if max_prefix is None:
                    max_prefix = 32
                while prefix >= max_prefix:
                    network = nth_ipv6(f"{netID}/{prefix}", 0)
                    networks.append(network)
                    prefix -= 1
        return networks

class MAC:
    def __init__(self, mac):
        self.addr = mac
    def __repr__(self):
        """ to be used as representation for developers """
        return f"{self.addr}"
    def __str__(self):
        """ returns 'address' """
        return f"{self.addr}"
    @property
    def addr(self):
        """ returns the address of the IP """
        return self.__addr
    @addr.setter
    def addr(self, mac):
        """ sets the value of addr and recalculates valid """
        match = re.match(r"(([\da-f]{2}[:\-.]){5}[\da-f]{2}|([\da-f]{4}[:\-.]){2}[\da-f]{4}|[\da-f]{12})", mac.lower())
        if match is not None:
            self.__addr = re.sub(r"[:\-.]", '', mac.lower())
        else:
            self.__addr = None
        self.valid = None
    @property
    def valid(self):
        """ returns True if the MAC is valid """
        return self.__valid
    @valid.setter
    def valid(self, placeholder):
        """ sets the value of valid to True if the MAC is valid """
        self.__valid = valid_mac(self.addr)
    @property
    def multicast(self):
        """ returns True if the MAC is a multicast MAC (0100.5eXX.XXX) """
        if self.valid:
            return self.addr[0:6] == '01005e'
        return False
    @property
    def broadcast(self):
        """ returns True if the MAC is a broadcast MAC (ffff.ffff.ffff) """
        if self.valid:
            return self.addr == 'ffffffffffff'
        return False
    def format(self, char, case='lower'):
        """ returns the MAC formatted with the character specified """
        return format_mac(self.addr, char=char, case=case)

