#!/usr/bin/python3.6

# imported for pings
import os
import subprocess
# imported for SSH
import pexpect
from io import BytesIO
# import for SSH responses
import re

import parse as p

default_user = 'less-tools'
passDir = '/var/www/html/files/pass/'

def parse_cmd(cmd):
    parse_string = ""
    # get valid pieces of the command
    pieces = cmd.split(' |? ', 1)
    # get the cmd
    cmd = pieces[0]
    # look at the text-parsing piece
    if len(pieces) > 1:
        parse_string = pieces[1]
    return cmd, parse_string

def has_attrs(class_obj, class_attrs):
    """ returns True if all attributes exist and contain a value """
    # if only one attribute was supplied
    if type(class_attrs) == str:
        # check if the attribute exists and has a value
        return getattr(class_obj, class_attrs, None) is not None
    # if an array of attributes were supplied
    elif type(class_attrs) == list:
        # for each attribute supplied
        for class_attr in class_attrs:
            # check if the attribute exists and has a value
            if getattr(class_obj, class_attr, None) is None:
                return False
        return True

def missing_attr(class_obj, class_attr):
    """ returns True if attribute doesn't exist or doesn't contain a value """
    return getattr(class_obj, class_attr, None) is None

def pingable(ip, timeout=1, count=1):
    """ returns True if the host responds to a single ping """
    for i in range(count):
        FNULL = open(os.devnull, 'w')
        command = ['ping', '-c', '1', '-W', str(timeout), ip]
        return_code = subprocess.call(command, stdout=FNULL, stderr=subprocess.STDOUT)
        FNULL.close()
        # if the ping was successful
        if return_code == 0:
            return True
    return False

def get_user(device):
    """ returns the default user for a device model """
    if device.model in ['EC', 'DNCS']:
        return 'ecstaging'
    elif device.model == 'DAC':
        return 'acc4000d'
    elif device.model == 'MBO':
        return 'mystro'
    else:
        return default_user

def get_passFile(user):
    """ returns the location of the password file """
    return f"{passDir}{user}"

def read_passFile(passFile):
    """ returns the password in the password file """
    # open the password file
    with open(passFile) as inFile:
        # read the file into memory
        output = inFile.read()
    # for each line
    for line in output.split('\n'):
        # strip the line on unnecessary characters
        passwd = line.strip()
        # if line has characters
        if len(passwd) > 2:
            # return the line
            return passwd

def get_expect(full=True):
#    expect = [
 #       r"(?m)^(\r)?(\x1b\[(\?7h|K))?(\*)?([)?([\w\-/]+[@:])?[\w\-]+(\[A/U\])?(\([ \w\-]+\))?([ :]~)?(])?(>([\w\-]+)+>)?(>)?([\w\-]+>)*[$#>%]",
  #      r"(?m)^\$",
   #     r"(?m)^[\w\-/]+@\([\w\-]+\)(\([\w\-/ ]+\))+\(tmos\)#",
    #    r"(?m)^--:- / cli->"
#    ]
 #       expect += [
  #          r"ftp>",
   #         r"Name \(\S*\):"
    #        r">>",
     #       r".+\? \[y/n\]",
      #      r"username:",
       #     r"nrcmd>"
        #]
    # combining all
    expects = [
        # starting line
        r"(?m)^"+
        # special starting characters some devices begin lines with
        r"(\r)?(\x1b\[(\?7h|K))?"+
        # start of all options
        r"("+
        # for FTP, nrcmd, and SQL database commands
        r"(ftp|nrcmd|\d+>)>"+
        # most common
        r"|"+r"(\*)?([)?([\w\-/]+[@:])?(?P<name>[\w\-]+)(\[A/U\])?(\([ \w\->]+\))?([ :](~|[\w\-]+))?(])?(>([\w\-]+)+>)?[$#>%][ ]?"+
        # Linux
        r"|"+r"\$"+
        # some weird devices
        r"|"+r"[\w\-/]+@\([\w\-]+\)(\([\w\-/ ]+\))+\(tmos\)#"+
        # console servers
        r"|"+r"--:- / cli->"+
        # password prompt
        r"|"+r"[Pp]assword:"
    ]
    # if getting a full expect (typically used when not initially connecting)
    if full:
        # add misc. options
        expects += [
            r"|"+r"Name \(\S+\):"+r"|"+r"\? \[y/n\]"+r"|"+r"username:"
        ]
    # end of all options
    expects += [r")"]
    # combine options
    expect = ''
    for option in expects:
        expect += option
    return expect

def get_response(device, cmds, timeout=10):
    """ executes one or more commands and returns the response """
    no_error = True
    # if the session does not exist
    if device.session is None:
        return ''
    # ensure cmds is an array
    if type(cmds) == str:
        cmds = [cmds]
    # create a binary IO to stream responses into
    binary_response = BytesIO()
    device.session.logfile_read = binary_response
    try:
        # for each command
        for cmd in cmds:
            # send the command to the session
            device.session.sendline(cmd)
            # wait for the command to finish
            device.session.expect(device.expect, timeout=timeout)
        # look for 'unknown command' for Juniper devices -- ignore if syntax error is thrown from a GAC
        if re.search(b"(unknown command|syntax error)", binary_response.getvalue()) is not None:
            while re.search(b"\{master:\d+\}", binary_response.getvalue()) is None:
                index = device.session.expect([pexpect.TIMEOUT, device.expect], timeout=1)
                # if timed out looking for completion
                if index == 0:
                    break
    except Exception as error:
        #print(f"<pre>{error}</pre>")
        no_error = False
        # close the SSH session
        device.close()
    # decode full response
    response = binary_response.getvalue().decode('utf-8', 'ignore').replace('\r','')
    # if no error was generated
    if no_error:
        # get the current prompt
        new_line = response.rfind('\n')
        current_prompt = response[new_line:]
        # remove the current prompt
        response = response[:new_line]
    # if the previous prompt is stored
    if hasattr(device, '__previous_prompt'):
        # add the previous prompt
        response = device.__previous_prompt + response
    # store prompt for next command or clear is
    device.__previous_prompt = current_prompt if no_error else None
    # remove beginning and trailing new-lines
    response = p.remove_border_newlines(response)
#    print(f"Response:\n{response}\n\n")
 #   print(f"Closed: {device.session.closed}")
  #  print(f"After: '{device.session.after}'")
    return response

def get_responseNEW(device, cmds, timeout=10):
    """ executes one or more commands and returns the response """
    no_error = True
    cmds_run = 0
    # if the session does not exist
    if device.session is None:
        return ''
    # ensure cmds is an array
    if type(cmds) == str:
        cmds = [cmds]
    # create a binary IO to stream responses into
    binary_response = BytesIO()
    device.session.logfile_read = binary_response
    try:
        # for each command
        for cmd in cmds:
            # send the command to the session
            device.session.sendline(cmd)
            # wait for the command to finish
            device.session.expect(device.expect, timeout=timeout)
            # increment the count of commands run
            cmds_run += 1
        # find the number of expect matches
        expect_count = len(list(re.finditer(device.expect.encode(), binary_response.getvalue())))
        # for each extra expect found
        for i in range(expect_count - cmds_run):
            # look for extra expect
            device.session.expect([pexpect.TIMEOUT, device.expect], timeout=2)
    except Exception as error:
        print(f"<pre>{error}</pre>")
        no_error = False
        # close the SSH session
        device.close()
    # decode full response
    response = binary_response.getvalue().decode('utf-8', 'ignore').replace('\r','')
    # if no error was generated
    if no_error:
        # get the current prompt
        new_line = response.rfind('\n')
        current_prompt = response[new_line:]
        # remove the current prompt
        response = response[:new_line]
    # if the previous prompt is stored
    if hasattr(device, '__previous_prompt'):
        # add the previous prompt
        response = device.__previous_prompt + response
    # store prompt for next command or clear is
    device.__previous_prompt = current_prompt if no_error else None
    # remove beginning and trailing new-lines
    response = p.remove_border_newlines(response)
    print(f"Commands: {cmds} <> {cmds_run}\nExpects found: {expect_count}")
    print(f"Response:\n{response}\n\n")
#    print(f"Closed: {device.session.closed}")
 #   print(f"After: '{device.session.after}'")
    return response

def response_edits(device, response):
    # if this is a Nokia GAC and a command was run in configuration mode
#    if device.model == 'GAC' and response.startswith('\n\n[edit]\n'):
 #       response = response[9:]
    # if this is a Nokia 7360
    if device.model == '7360':
        response = re.sub(r"[ -|/\\]\S\[1D", '', response)
        # make each line only as long as needed
        lines = response.split('\n')
        full_max_length = 0
        max_length = 0
        for i in range(len(lines)):
            full_length = len(lines[i])
            if full_length > full_max_length:
                full_max_length = full_length
            length = len(lines[i].replace('-','').replace('=',''))
            if length > max_length:
                max_length = length
        if full_max_length != max_length:
            for i in range(len(lines)):
                lines[i] = lines[i][:max_length+2]
            response = '\n'.join(lines)
    return response

class Device:
    # initialize class
    def __init__(self, data):
        """ initialize a Device class """
        self.__name = data.get('name')
        self.__ip = data.get('ip')
        self.__os = data.get('os')
        self.__vendor = data.get('vendor')
        self.__model = data.get('model')
        self.__expect = get_expect(full=True)
    def __repr__(self):
        """ to be used as representation for developers """
        repr_str = ''
        repr_str = f"Device({{'{self.name}', '{self.ip}')"
    def __str__(self):
        """ returns 'hostname (ip)' """
        return f"{self.name} ({self.ip})"
    @property
    def name(self):
        return self.__name
    # name setter
    @name.setter
    def name(self, value):
        self.__name = value
    @property
    def ip(self):
        return self.__ip
    # ip setter
    @ip.setter
    def ip(self, value):
        self.__ip = value
    @property
    def os(self):
        return self.__os
    # os setter
    @os.setter
    def os(self, value):
        self.__os = value
    @property
    def vendor(self):
        return self.__vendor
    # vendor setter
    @vendor.setter
    def vendor(self, value):
        self.__vendor = value
    @property
    def model(self):
        return self.__model
    # model setter
    @model.setter
    def model(self, value):
        self.__model = value
    @property
    def expect(self):
        return self.__expect
    # expect setter
    @expect.setter
    def expect(self, value):
        self.__expect = value
    @property
    def up(self):
        """ returns True if the host responds to a ping """
        return pingable(self.ip, timeout=1, count=2)
    @property
    def connected(self):
        """ returns True if an SSH session is established """
        return has_attrs(self, 'session') and self.session.closed is False
    @property
    def closed(self):
        """ returns True if an SSH session is not established """
        return not has_attrs(self, 'session') or self.session.closed is True
    def connect(self, timeout=15, expect=None, user=None, passFile=None):
        """ opens an SSH session """
        # store user
        if user is None:
            self.user = get_user(self)
        else:
            self.user = user
        # get expect
        if expect is None:
            expect = get_expect(full=False)
        # get password file
        if passFile is None:
            self.passFile = get_passFile(self.user)
        else:
            self.passFile = passFile
        # create command and open SSH session
        try:
            cmd = f"sshpass -f {self.passFile} ssh -l {self.user} {self.ip}"
            #print(cmd)
            self.session = pexpect.spawn(cmd)
            # if this is a terminal device (fix for ADTRAN 9504N and ADTRAN 9516)
            if self.session.isatty() is True:
                # set the terminal size to 10000 length (vertical) and 8000 chars wide (horizontal)
                self.session.setwinsize(10000, 8000)
            # create a binary IO to stream responses into
            with BytesIO() as self.session.logfile_read:
                # wait 15 seconds (timeout) for session to open
                self.session.expect(expect, timeout=timeout)
        except:
            pass
        return self.session
    def close(self):
        """ closes the SSH session with the device """
        # is an SSH session is open
        if self.connected:
            # send exit command
            self.session.sendline('exit')
            # close and clear the session
            self.session.close()
            self.session = None
    def get_response(self, cmds, timeout=10, expect=None):
        """ executes one or more commands and returns the response """
        if type(cmds) is not list:
            cmds = [cmds]
        # if SSH session is not open
        if self.closed:
            # return None
            self.response = None
            return self.response
        # if this is first command being sent
        if not hasattr(self, '__previous_prompt'):
            # send blank line to get prompt
            get_response(self, [''], timeout=timeout)
        # seperate command with parsing
        cmd_list = []
        no_parsing_cmds = []
        # for each command
        for cmd in cmds:
            # if parsing was specified
            if len(cmd.split(' |? ')) > 1:
                # if any previous non-parsing commands were found
                if len(no_parsing_cmds) > 0:
                    # add them to the final list
                    cmd_list.append(no_parsing_cmds)
                    # clear the array
                    no_parsing_cmds = []
                # add the parsing command to the list
                cmd_list.append(cmd)
            # if no parsing was specified
            else:
                # add it to the non-parsing array
                no_parsing_cmds.append(cmd)
        # if any non-parsing commands were not added
        if len(no_parsing_cmds) > 0:
            # add them to the final list
            cmd_list.append(no_parsing_cmds)
        # initialize a string
        response = ''
        # for each command
        for i in range(len(cmd_list)):
            # if the command is a list/array
            if type(cmd_list[i]) is list:
                # run the commands and add the output to the final string
                response += get_response(self, cmd_list[i], timeout=timeout)+'\n'
            else:
                # seperate the command from the parsing pattern
                cmd, parse_string = parse_cmd(cmd_list[i])
                # send the command
                cmd_response = get_response(self, cmd, timeout=timeout)
                # get the command line
                first_new_line = cmd_response[1:].find('\n')
                # add the parse string to the command line
                response += cmd_response[:first_new_line+1].strip()+' | '+parse_string+'\n'
                # parse the response and add it to the final string
                response += p.parse_lines(parse_string, cmd_response[first_new_line+1:])+'\n'
            # remove beginning and trailing new-lines
            response = p.remove_border_newlines(response)
            # make special edits to make output 'prettier'
            self.response = response_edits(self, response)
        return self.response

