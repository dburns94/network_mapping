#!/usr/bin/python3.6

import pexpect
from io import BytesIO
import re_ext

# SAMPLE
## import pexpect_ext as p_ext
## [user, passFile] = p_ext.getLoginInfo()
## expec = p_ext.getExpec(hostname, deviceType)
## session = p_ext.openSession(ip, expec, user, passFile)
## p_ext.noPaging(session, expec, deviceType)
## lines = p_ext.sendCMD(session, cmd, expec, timeLimit)
## p_ext.exitSession(session)

def getLogin(user="less-tools"):
    passFile = ""
    if user == "whoami":
        passFile = "/var/www/html/files/pass/whoami"
    elif user == "less-tools":
        passFile = "/var/www/html/files/pass/less-tools"
    elif user == "acc4000d":
        passFile = "/var/www/html/files/pass/acc4000d"
    elif user == "mystro":
        passFile = "/var/www/html/files/pass/mystro"
    return [user, passFile]

def getExpec(hostname, deviceType):
    expec = hostname + "[\S ]{0,30}[#>]"
    return expec

def noPaging(session, expec, deviceType):
# disable output paging on a device
    if deviceType == "C100G":
        cmd = "page-off"
        sendCMD(session, cmd, expec, 5)
    elif deviceType in ["E6000", "9504N", "9516"]:
        cmd = "terminal length 0"
        sendCMD(session, cmd, expec, 5)
    elif deviceType in ["CBR8", "9500", "4500", "3850", "ASR9K", "CRS-X"]:
        cmd = "terminal length 0"
        sendCMD(session, cmd, expec, 5)
        cmd = "terminal width 0"
        sendCMD(session, cmd, expec, 5)

def openSession(ip, expec, user, passFile, timeout=15):
# open an SSH session and throw away any initial login data, like:
# login banner, message of the day, etc.
    # open the session
    session = pexpect.spawn("sshpass -f %s ssh -l %s %s" % (passFile, user, ip))
#  print("sshpass -f %s ssh -l %s %s" % (passFile, user, ip))
    # create a binary IO to stream responses into
    result = BytesIO()
    session.logfile_read = result
    # wait 15 seconds for session to open
    session.expect(expec, timeout=timeout)
    return session

def sendCMD(session, cmd, expec, timeLimit):
# executes a command and returns the output
    try:
        # create a binary IO to stream responses into
        result = BytesIO()
        session.logfile_read = result
        # send the command to the session
        session.sendline(cmd)
        # wait for the command to finish
        session.expect(expec, timeout=timeLimit)
        # decode the binary responses
        resultString = result.getvalue().decode("utf-8")
        # convert the response string into an array of strings
        output = resultString.split("\n")
        # remove all return characters from the response
        for i in range(0,len(output)):
            output[i] = output[i].replace("\r","")
    # if the command did not finish in the specified time limit,
    # close the session and return "Failed"
    except Exception as error:
        exitSession(session)
        output = result.getvalue().decode("utf-8")
    return output

def getOutput(session, cmd, expec, timeout=10):
# executes a command and returns the output
    try:
        # create a binary IO to stream responses into
        result = BytesIO()
        session.logfile_read = result
        # send the command to the session
        session.sendline(cmd)
        # wait for the command to finish
        session.expect(expec, timeout=timeout)
        # decode the binary responses
        resultString = result.getvalue().decode("utf-8")
        # convert the response string into an array of strings
        output = resultString.replace("\r","")
        output = output[:output.rfind("\n")]
    # if the command did not finish in the specified time limit,
    # close the session and return "Failed"
    except Exception as error:
        exitSession(session)
        resultString = result.getvalue().decode("utf-8")
        output = resultString.replace("\r","")
    return output

def parseCmdString(cmdString, default_expect, default_timeout): 
    cmds = [] 
    for cmd in cmdString.split("\n"): 
        cmd_expect = default_expect 
        timeout = default_timeout 
        if len(cmd) > 0: 
            # check if user specified a different timeout 
            pieces = cmd.split(" |? ") 
            # if user specified a different expect 
            if len(pieces) > 1 and len(pieces[1].strip()) != 0: 
                try: 
                    timeout = int(pieces[1].strip()) 
                except: 
                    pass 
            # if the user specified a different expect 
            if len(pieces) > 2 and len(pieces[2].strip()) != 0: 
                cmd_expect = pieces[2].strip() 
            # create cmd array 
            cmd = [pieces[0].strip(), cmd_expect, timeout] 
            # add it to the final array 
            cmds.append(cmd) 
    return cmds 

def getOutputSet(session, cmds):
# executes a command and returns the output
    try:
        # create a binary IO to stream responses into
        result = BytesIO()
        session.logfile_read = result
        for cmd in cmds:
            expec = cmd[1]
            timeLimit = cmd[2]
            # send the command to the session
            session.sendline(cmd[0])
            # wait for the command to finish
            session.expect(expec, timeout=timeLimit)
        # decode the binary responses
        resultString = result.getvalue().decode("utf-8")
        # convert the response string into an array of strings
        output = resultString.replace("\r","")
        output = output[:output.rfind("\n")]
    # if the command did not finish in the specified time limit,
    # close the session and return "Failed"
    except Exception as error:
        exitSession(session)
        resultString = result.getvalue().decode("utf-8")
        output = resultString.replace("\r","")
    return output

def sendCMD_set(session, cmds, expec, timeLimit):
    # executes a set of commands and returns the output
    try:
        # create a binary IO to stream responses into
        result = BytesIO()
        session.logfile_read = result
        # send an empty line
        session.sendline("")
        # wait for the command to finish
        session.expect(expec, timeout=timeLimit)
        # send the commands to the session
        for cmd in cmds:
            session.sendline(cmd)
            # wait for the command to finish
            session.expect(expec, timeout=timeLimit)
        # decode the binary responses
        resultString = result.getvalue().decode("utf-8")
        # convert the response string into an array of strings
        output = resultString.split("\n")
        # remove all return characters from the response
        for i in range(0,len(output)):
            output[i] = output[i].replace("\r","")
    # if the command did not finish in the specified time limit,
    # close the session and return "Failed"
    except Exception as error:
        exitSession(session)
        resultString = result.getvalue().decode("utf-8")
        output = resultString.split("\n")
    return output

def exitSession(session):
# close the session
    session.sendline("exit")
    session.close()

def getDeviceType(session, expec):
    # disable paging
    cmd_set = ["terminal length 0",
                          "terminal width 0",
                          "page-off"
                        ]
    for cmd in cmd_set:
        getOutput(session, cmd, expec, timeout=5)

    cmd = "admin show inventory | utility egrep \"CRS-|ASR-\""
    output = getOutput(session, cmd, expec, timeout=30)
    # look for Cisco ASR-9K
    pattern = r"PID:[ ]+ASR-9\d+-"
    if re_ext.getMatch(output, pattern) != None:
        return "ASR9K"
    # look for Cisco CRS-X
    pattern = r"PID:[ ]+CRS-\d+-"
    if re_ext.getMatch(output, pattern) != None:
        return "CRS-X"

    cmd = "show version"
    output = getOutput(session, cmd, expec, timeout=30)
    # look for ARRIS E6000
    pattern = r"Chassis[ ]+Type:[ ]+E6000"
    if re_ext.getMatch(output, pattern) != None:
        return "E6000"
    # look for Cisco CBR8
    pattern = r"Cisco[ ]+cBR-8"
    if re_ext.getMatch(output, pattern) != None:
        return "CBR8"
    # look for ADTRAN
    pattern = r"\bADTRAN\b"
    if re_ext.getMatch(output, pattern) != None:
        # look for 9504N
        pattern = r"\b9504N\b"
        if re_ext.getMatch(output, pattern) != None:
            return "9504N"
        # look for 9516
        pattern = r"\b9516\b"
        if re_ext.getMatch(output, pattern) != None:
            return "9516"
    # look for Cisco 3850
    pattern = r"Model[ ]+Number[ ]+:[ ]+WS-C3850-"
    if re_ext.getMatch(output, pattern) != None:
        return "3850"

    cmd = "show system | include Product"
    output = getOutput(session, cmd, expec, timeout=30)
    # look for CASA C100G
    pattern = r"C100G"
    if re_ext.getMatch(output, pattern) != None:
        return "C100G"

    cmd = "show license udi"
    output = getOutput(session, cmd, expec, timeout=30)
    # look for Cisco 9500
    pattern = r"\bC9500\b"
    if re_ext.getMatch(output, pattern) != None:
        return "9500"
    # look for Cisco 4500
    pattern = r"\bC4500X\b"
    if re_ext.getMatch(output, pattern) != None:
        return "4500"

    cmd = "show software-mngt oswp"
    output = getOutput(session, cmd, expec, timeout=30)
    # look for Nokia 7360
    pattern = r"oswp[ ]+table"
    if re_ext.getMatch(output, pattern) != None:
        return "7360"
    return "Unknown"


