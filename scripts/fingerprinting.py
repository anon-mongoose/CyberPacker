#!/bin/usr/python3
import hashlib, base64, sys

try:
    import os
except ModuleNotFoundError:
    print("os module missing. May not get some info.")
    pass



def main():
    #Messages
    msgHelp =  f" This script fingerprints a machine. The result is the concatenation of data gathered and its sha256 hash.\n\n The parametters are the following:\n"
    msgHelp += f"   I   Machine ID (best)\n   M   MAC Address\n   A   Architecture of the processor\n   C   Number of logical cores of the machine\n"
    msgHelp += f"   R   RAM amount in GB\n   O   Operating System name (Linux, Windows...)\n   H   Hostname\n\nExamples:\n"
    msgHelp += f"   {sys.argv[0]}  -h, --help                  Print this help message\n"
    msgHelp += f"   {sys.argv[0]}  -f, --file  [FILE PATH]     Fingerprints a machine based on info in a file (see the notes below)\n"
    msgHelp += f"   {sys.argv[0]}  [IMACROH]                   Fingerprints this machine based on the specified parameters\n"
    msgHelp += f"   {sys.argv[0]}  MOH                         Fingerprints this machine based on its MAC Address, OS and Hostname\n"
    msgHelp += f"   {sys.argv[0]}  ACMR                        Fingerprints this machine based on its Architecture, Core numbers, MAC Address and RAM amount\n"
    msgHelp += f"   {sys.argv[0]}  IMACROH                     Fingerprints this machine based on all parametters available\n\n"
    msgHelp += f"   Notes:\n    If you use the fingerprint method based on file, this one must look like this:\n"
    msgHelp += f"      MACHINE_ID=\n      MAC=\n      ARCH_PROC=\n      CORES=\n      RAM_GB=\n      OS=\n      HOSTNAME=\n"
    msgHelp += f"    Only fill the fields you want to base the fingerprint on and let the others empty."



    msgUsage = f" Usage:  {sys.argv[0]}  <options>\n See {sys.argv[0]}  --help for more information."

    #Correct chars
    correctChars = "IMACROH"

    # Default dic
    fingerprintDic = {"MACHINE_ID" : "",
                      "MAC" : "",
                      "ARCH_PROC" : "",
                      "CORES" : "",
                      "RAM_GB" : "",
                      "OS" : "",
                      "HOSTNAME" : ""}

    # Test args
    if len(sys.argv) < 2 or len(sys.argv) > 3 :
        print(msgUsage)
        return 0

    if len(sys.argv)==2 and (sys.argv[1]=="-h" or sys.argv[1]=="--help"):
        print(msgHelp)
        return 1

    elif len(sys.argv)==2 and checkArg(sys.argv[1].upper(), correctChars):
        # Keeping only unique chars
        uniqueArg = ""
        for char in sys.argv[1].upper():
            if char not in uniqueArg:
                uniqueArg += char
        enckey = fingerprintFromMachine(fingerprintDic, uniqueArg)
        print(enckey)
        return 1

    elif len(sys.argv)==3 and (sys.argv[1]=="-f" or sys.argv[1]=="--file"):
        enckey = fingerprintFromFile(fingerprintDic, sys.argv[2])
        print(enckey)
        return 1

    else:
        print("nok")




# Check the arg validity
def checkArg(argString, correctChars):
    nbCorrectChars = 0
    for char in argString:
        for correctChar in correctChars:
            if char == correctChar:
                nbCorrectChars += 1
    if len(argString) == nbCorrectChars:
        return True
    else:
        return False



# Getting info from file
def fingerprintFromFile(dic, filePath):
    try:
        fpFile = open(filePath, "r")
    except FileNotFoundError:
        print("File not found. Please, check if the path is valid or the file exists.")
        return "#NONE#"

    for line in fpFile.readlines():
        try:
            splitLine = line.split("=")
            print(splitLine)
            if (splitLine[0] == "MAC" or splitLine[0] == "OS") and splitLine[1] != "\n":
                dic[splitLine[0]] = splitLine[1][:-1].upper()
            elif (splitLine[0] == "ARCH_PROC" or splitLine[0] == "MACHINE_ID" or splitLine[0] == "HOSTNAME") and splitLine[1] != "\n":
                dic[splitLine[0]] = splitLine[1][:-1].lower()
            elif splitLine[1] != "\n":
                dic[splitLine[0]] = splitLine[1][:-1]
        except KeyError:
            print("Err")
            pass
    fpFile.close()

    return generateEK(dic)




# Getting info directly from machine
def fingerprintFromMachine(dic, uniqueArg):
    if "I" in uniqueArg:
        cmdOutput = str(os.popen("cat /etc/machine-id").read())
        dic["MACHINE_ID"] = cmdOutput[:-1] # to remove the \n

    if "M" in uniqueArg:
        try:
            import uuid, re
            dic["MAC"] = ':'.join(re.findall('..', '%012x' % uuid.getnode())).upper()
        except ModuleNotFoundError:
            print("uuid or re module missing. Cannot get MAC Address.")

    if "A" in uniqueArg or "O" in uniqueArg:
        try:
            import platform
            if "A" in uniqueArg:
                dic["ARCH_PROC"] = platform.processor().lower()
            if "O" in uniqueArg:
                dic["OS"] = platform.system().upper().upper()
        except ModuleNotFoundError:
            print("platform module missing. Cannot get OS and System Architecture.")

    if "C" in uniqueArg:
        try:
            import multiprocessing
            dic["CORES"] = str(multiprocessing.cpu_count())
        except ModuleNotFoundError:
            print("multiprocessing module missing. Cannot get CPU cores number.")

    if "R" in uniqueArg:
        try:
            import psutil
            dic["RAM_GB"] = str(round(psutil.virtual_memory().total / (1024.0 **3)))
        except ModuleNotFoundError:
            try:
                cmdOutput = os.popen("grep MemTotal /proc/meminfo").read()
                tmp = ""
                for char in cmdOutput:
                    if char.isdigit():
                        tmp += char
                dic["RAM_GB"] = str((round(int(tmp) / (1024.0), -3))/1000)
            except NameError:
                print("psutil module missing. Cannot get RAM amount.")

    if "H" in uniqueArg:
        try:
            import socket
            dic["HOSTNAME"] = socket.gethostname().lower()
        except ModuleNotFoundError:
            print("socket module missing. Cannot get hostname.")

    return generateEK(dic)



# Building an encryption key
def generateEK(fpdic):
    partEncryptionKey = ""
    nbEmptyField = 0
    for key in fpdic:
        if fpdic[key] != "":
            partEncryptionKey += fpdic[key]
        else:
            nbEmptyField += 1

    # Minimum one field required
    if nbEmptyField != len(fpdic):
        print(partEncryptionKey)
        partEncryptionKey = str.encode(partEncryptionKey)
        partEncryptionKey = hashlib.sha256(partEncryptionKey).hexdigest()
    else:
        partEncryptionKey = "#NONE#"

    return "EK="+partEncryptionKey


main()
