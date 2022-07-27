#!/bin/python3
'''
Purpose: Build the hxhBl00dlust
Author: Bryan Angeles (hxhBroFessor)
Usage: ./hxhBl00dlust.py

'''

# Globals
PKG_MGR = 'apt'
hxhBl00dlust_DIR = '/opt/hxhBl00dlust/'
BUILD_LOG = 'hxhBl00dlust.log'
LOG = hxhBl00dlust_DIR + BUILD_LOG

# Minimal Package list to get started
starterPackagesList = [
    'net-tools',
    'curl',
    'git'
    ]

# List of packages to have APT install. Change if you want. You break it you buy it.
aptPackageList = [
    'tmux',
    'torbrowser-launcher',
    'nmap',
    'smbclient',
    'locate',
    'dirb',
    'gobuster',
    'medusa',
    'masscan',
    'whois',
    'hashcat',
    'airgraph-ng',
    'dnsenum',
    'dnsmap',
    'ettercap-common',
    'ettercap-graphical',
    'netdiscover',
    'sqsh',
    'chromium-browser',
    'python3-pandas',
    'terminator',
    'flameshot',
    'sqlmap',
    'nikto',
    'wapiti',
    'onesixtyone',
    'smbclient',
    'smbmap',
    'sslscan',
    'whatweb',
    'python3-shodan',
    'webhttrack',
    'stegosuite',
    'exifprobe',
    'recon-ng',
    'ffuf',
    'mousepad',
    'jq'

    ]

# List of packages to have SNAP install. Change if you want. You break it you buy it.
snapPackageList = [
    #'chromium',
    #'sqlmap',
    'john-the-ripper',
    'dalfox'
    ]

# Snaps that need --classic
# Avoid these. It's better to scrape a git for the latest and install. Zaproxy is a great example.
snapClassicPackageList =[
    #'zaproxy'
    'code'
]

########################################################
# Colors
GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
NOCOLOR = '\033[m'

from datetime import datetime
from getpass import getpass
from hashlib import sha1
from os import geteuid,path,makedirs
from os.path import expanduser
from subprocess import run
from urllib.request import urlopen
from requests import get
from re import search

# Check that the user is root
def checkIfRoot():
    if geteuid() != 0:
            print(RED + '[!] You need sudo/root permissions to run this... exiting.' + NOCOLOR)
            exit(0)

# Check for internet connection
def checkForInternet():
    try:
        check = urlopen('https://www.google.com', timeout=3.0)
        print(GREEN +'[+] Internet connection looks good!' + NOCOLOR)
    except:
        print(RED + '[-] Internet connection looks down. You will need internet for this to run (most likely). Fix and try again.' + NOCOLOR)
        exit(1)

def initNotice():
    print('[!] This script requires user input once or twice.\n\
    [!] It is not completely "Set and Forget".')
    nullInput = input('Hit Enter.')

# Get starting Disk Room
def freeSpaceStart():
    # Needs Regex Impovement with RE Search. Non Gig sized systems will break this.
    global FREE_SPACE_START_INT
    freeSpaceStart = run(['df -h /'],shell=True,capture_output=True).stdout.decode().split('G')[2].strip()
    writeToLog('[i] Gigs of Free Space on / at the Start of the build: ' + freeSpaceStart + 'G')
    FREE_SPACE_START_INT = float(freeSpaceStart)
    return(FREE_SPACE_START_INT)

def freeSpaceEnd():
    # Needs Regex Impovement with RE Search. Non Gig sized systems will break this.
    freeSpaceEnd = run(['df -h /'],shell=True,capture_output=True).stdout.decode().split('G')[2].strip()
    writeToLog('[i] Gigs of Free Space on / at the Start of the build: ' + freeSpaceEnd + 'G')
    freeSpaceEndInt = float(freeSpaceEnd)
    spaceUsed = FREE_SPACE_START_INT - freeSpaceEndInt
    writeToLog('[i] Gigs of Space used for hxhBl00dlust Buildout: ' + str(spaceUsed) + 'G')

# Check/Inform about for unattended upgrade
def informAboutUnattendedUpgade():
    print('[!][!][!][!][!][!][!][!]\nUnattended Upgades firing while this script is running will break it.\
    \nKill or complete the upgrades if you recently booted or rebooted. Then continue.\
    \nIT MAY REQUIRE A REBOOT! If so, kill this script. Reboot. Run the updates. Run this script again.')
    nullInput = input('Hit any key to continue.')

def createhxhBl00dlustDir(hxhBl00dlust_DIR):
    print('[*] Creating hxhBl00dlust Dir at:',hxhBl00dlust_DIR)
    try:
        makedirs(hxhBl00dlust_DIR, exist_ok=True)
    except FileExistsError:
        print('[i] ' + hxhBl00dlust_DIR + ' already exists. Continuing.')
    except Exception as e:
        print('[-] Error creating the ' + hxhBl00dlust_DIR + '. Error ' + str(e))

def startLogFile():
    try:
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        if not path.isfile(LOG):
            with open(LOG, 'a') as log:
                log.write(now + " - Log Started.\n")
            return('Succeeded')
        else:
            with open(LOG, 'a') as log:
                log.write(now + " - Log Started. Strange, the log file appears to exist already?  Continuing anyways.\n")
            return('Succeeded')
    except:
        return('Failed')
        # For now just simply exit here
        exit(1)

def writeToLog(stringToLog):
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(LOG, 'a') as log:
        log.write(now + " - " + stringToLog + '\n')
    if '[+]' in stringToLog:
        print('\n' + GREEN + stringToLog + NOCOLOR + '\n----------------------------------------------------------\n')
    elif '[-]' in stringToLog:
        print('\n' + RED + stringToLog + NOCOLOR + '\n----------------------------------------------------------\n')
    elif '[i]' in stringToLog + NOCOLOR:
        print('\n' + YELLOW + stringToLog + NOCOLOR + '\n----------------------------------------------------------\n')
    else:
        print('\n' + stringToLog + '\n----------------------------------------------------------\n')

def buildStarterPackageList():
    listOfPackagesCommand = ''
    for package in starterPackagesList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

def buildAptPackageList():
    listOfPackagesCommand = ''
    for package in aptPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

def buildSnapPackageList():
    listOfPackagesCommand = ''
    for package in snapPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

def buildSnapClassicPackagesList():
    listOfPackagesCommand = ''
    for package in snapClassicPackageList:
        listOfPackagesCommand = (listOfPackagesCommand + ' ' + package).strip()
    return(listOfPackagesCommand)

# apt update
def updateOS():
    #writeToLog('[+] Beginning OS updates...')
    try:
        run(['/usr/bin/apt','update'])
    except Exception as e:
        writeToLog('[-] APT Updating failed. Fix and try again. Error:',str(e))
        exit(1)
    try:
        run(['/usr/bin/apt','upgrade','-y'])
    except Exception as e:
        writeToLog('[-] APT Updating failed. Fix and try again. Error:',str(e))
        exit(1)
    try:
        run(['/usr/bin/apt','dist-upgrade','-y'])
    except Exception as e:
        writeToLog('[-] APT Updating failed. Fix and try again. Error:',str(e))
        exit(1)

# Minimal packages
def installStarterPackages():
    starterPackages = buildStarterPackageList()
    writeToLog('[*] Attempting installation of the following starter packages: ' + starterPackages)
    try:
        run(['/usr/bin/apt install -y ' + starterPackages],shell=True)
        writeToLog('[+] Starter Packages installed.')
    except Exception as e:
        writeToLog('[-] Starter Packages installation failed:',str(e))


# install base packages
def installAPTandSNAPPackages():
    aptPackages = buildAptPackageList()
    snapPackages = buildSnapPackageList()
    snapClassicPackages = buildSnapClassicPackagesList()
    writeToLog('[*] Attempting installation of the following ATP packages: ' + aptPackages)
    try:
        run(['/usr/bin/apt install -y ' + aptPackages],shell=True)
        writeToLog('[+] APT Packages installed.')
    except Exception as e:
        writeToLog('[-] APT Packages installation failed:',str(e))
    writeToLog('[*] Attempting installation of the following Snap Packages: ' + snapPackages)
    try:
        run(['/usr/bin/snap install ' + snapPackages],shell=True)
        writeToLog('[+] Snap Packages installed.')        
    except Exception as e:
        writeToLog('[-] Snap packages installation failed:',str(e))
    if len(snapClassicPackages) == 0:
        writeToLog('[*] No snap classics to install.')
        return
    writeToLog('[*] Attempting installation of the following Snap Classic Packages: ' + snapClassicPackages)
    for package in snapClassicPackageList:
        try:
            run(['/usr/bin/snap install --classic ' + package],shell=True)
            writeToLog('[+] Snap Classic ' + package + ' installed.')
        except Exception as e:
            writeToLog('[-] Snap packages ' + package + ' failed:',str(e))

# Swap Netcats
# Change out netcat-bsd for netcat-traditional
def swapNetcat():
    writeToLog('[*] Attempting to trade out netcat-bsd for netcat-traditional')
    try:
        run(['/usr/bin/apt purge  -y netcat-openbsd'],shell=True)
        run(['/usr/bin/apt install -y netcat-traditional'],shell=True)
        writeToLog('[+] netcat-traditional installed.')
    except Exception as e:
        writeToLog('[-] Installation of netcat-traditional failed. Error: '+str(e))

# Metasploit Framework
def installMSF():
    writeToLog('[+] Installing Metasploit Framework.')
    try:
        run(['/usr/bin/curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall'],shell=True)
        run(['/usr/bin/chmod 755 msfinstall'],shell=True)
        run(['./msfinstall'],shell=True)
        writeToLog('[+] MSF Installed Successfully.')
    except Exception as e:
        writeToLog('[-] Something went wrong during the MSF install. Error: ' + str(e))

# Install wordlists
    # Git clone the default wordlists
    # Add Rockyou2021
    # Add fuzzing list for burp/SQLI (xplatform.txt)
def installWordlists():
    # Error handling using git in this way (with run) sucks.
    writeToLog('[*] Installing Wordlists to /usr/share/wordlists')
    makedirs('/usr/share/wordlists/', exist_ok=True)
    try:
        run(['/usr/bin/git clone https://github.com/3ndG4me/KaliLists.git /usr/share/wordlists/'],shell=True)
        run(['/usr/bin/rm /usr/share/wordlists/README.md'],shell=True)
        run(['/usr/bin/gunzip /usr/share/wordlists/rockyou.txt.gz'],shell=True)
        writeToLog('[+] Kali default wordlists added and unpacked.')
    except Exception as e:
        writeToLog('[-] There was an error installing Kali default wordlists. Error: ' + str(e))
    try:
        run(['/usr/bin/git clone https://gitlab.com/kalilinux/packages/seclists.git /usr/share/wordlists/'],shell=True)
        run(['/usr/bin/rm /usr/share/wordlists/seclists/README.md'],shell=True)
        writeToLog('[+] Seclists wordlists added and unpacked.')
    except Exception as e:
        writeToLog('[-] There was an error installing Seclists wordlists. Error: ' + str(e))
    try:
        run(['/usr/bin/wget https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/xplatform.txt \
            -O /usr/share/wordlists/xplatform.txt'],shell=True)
        writeToLog('[+] Xplatform.txt SQLI Validation list added.')
    except Exception as e:
        writeToLog('[-] There was an error adding xplatform.txt. Error: ' + str(e))

#Install exploit-db
def installExploitDb():
    writeToLog('[*] Installing ExploitDB.')
    try:
        run(['/usr/bin/git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb'],shell=True)
        run(['/usr/bin/ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit'],shell=True)
        writeToLog('[+] Exploit DB Added.')
    except Exception as e:
        writeToLog('[-] There was an error installing ExploitDB. Error: ' + str(e))
    try:
        writeToLog('[*] Updating ExploitDB...')
        run(['/usr/local/bin/searchsploit -u'],shell=True)
        writeToLog('[+] Exploit DB Updated.')
    except Exception as e:
        writeToLog('[-] There was an error updating ExploitDB. Error: ' + str(e))


# Install Impacket
def installImpacket():
    writeToLog('[*] Installing Impacket.')
    try:
        run(['/usr/bin/git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket'],shell=True)
        run(['/usr/bin/python3 -m pip install /opt/impacket/.'],shell=True)
        # It seems that it takes running this twice to get it to complete
        run(['/usr/bin/python3 -m pip install /opt/impacket/.'],shell=True)
        writeToLog('[+] Impacket Installed.')
    except Exception as e:
        writeToLog('[-] There was an error installing Impacket. Error: ' + str(e))

# enum4Linux
def installEnum():
    writeToLog('[*] Installing Enum4Linux.')
    try:
        run(['/usr/bin/git clone https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux'],shell=True)
        run(['/usr/bin/ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux.pl'],shell=True)
        writeToLog('[+] Enum4Linux Installed.')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux. Error: ' + str(e))

# enum4linux
def installEnumNG():
    writeToLog('[*] Installing Enum4Linux-ng.')
    try:
        run(['/usr/bin/git clone https://github.com/cddmp/enum4linux-ng /opt/enum4linux-ng'],shell=True)
        run(['/usr/bin/ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng.py'],shell=True)
        writeToLog('[+] Enum4Linux-ng Installed.')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux-ng. Error: ' + str(e))

# Install WebShells
def installWebShells():
    writeToLog('[*] Installing Kali\'s Webshells')
    try:
        run(['/usr/bin/git clone https://gitlab.com/kalilinux/packages/webshells.git /usr/share/webshells'],shell=True)
        writeToLog('[+] Kali\'s WebShells Cloned to /usr/share/webshells')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux. Error: ' + str(e))

#Installing Feroxbuster
def feroxBuster():
    writeToLog('[*] Installing FeroxBuster')
    try:
        run(['/usr/bin/git clone https://gitlab.com/kalilinux/packages/feroxbuster.git /opt/feroxbuster'],shell=True)
        run(['/bin/bash /opt/feroxbuster/install-nix.sh'], shell=True)
        run(['/usr/bin/ln -sf /opt/feroxbuster/feroxbuster /usr/local/bin/feroxbuster'], shell=True)
        writeToLog('[+] Feroxbuster Cloned to /opt/feroxbuster')
    except Exception as e:
        writeToLog('[-] There was an error installing Feroxbuster. Error: ' + str(e))

def corsy():
    writeToLog('[*] Installing Corsy')
    try:
        run(['/usr/bin/git clone https://github.com/s0md3v/Corsy.git /opt/corsy'],shell=True)
        run(['/usr/bin/chmod +x /opt/corsy/corsy.py'], shell=True)
        run(['/usr/bin/ln -sf /opt/corsy/corsy.py /usr/local/bin/corsy.py'], shell=True)
        writeToLog('[+] Corsy Cloned to /opt/corsy')
    except Exception as e:
        writeToLog('[-] There was an error installing Corsy. Error: ' + str(e))

def theHarvestor():
    writeToLog('[*] Installing theHarvester')
    try:
        run(['/usr/bin/git clone https://github.com/laramies/theHarvester.git /opt/theHarvester'],shell=True)
        run(['/usr/bin/python3 -m pip install -r /opt/theHarvester/requirements/base.txt'], shell=True)
        run(['/usr/bin/ln -sf /opt/theHarvester/theHarvester.py /usr/local/bin/theHarvester.py'], shell=True)
        writeToLog('[+] theHarvester Cloned to /opt/theHarvester')
    except Exception as e:
        writeToLog('[-] There was an error installing theHarvester. Error: ' + str(e))

# Install Windows Resources
def installWindowsResources():
    writeToLog('[*] Installing Kali\'s Windows Resources')
    try:
        run(['/usr/bin/git clone https://gitlab.com/kalilinux/packages/windows-binaries.git /usr/share/windows-resources'],shell=True)
        writeToLog('[+] Kali\'s Windows Resources Cloned to /usr/share/webshells')
    except Exception as e:
        writeToLog('[-] There was an error installing Enum4Linux. Error: ' + str(e))

def hackTricks():
    writeToLog('[*] Installing Hacktrick\'s Wiki')
    try:
        run(['/usr/bin/git clone https://github.com/carlospolop/hacktricks.git /usr/share/hacktricks'],shell=True)
        writeToLog('[+] Hacktricks Cloned to /usr/share/hacktricks')
    except Exception as e:
        writeToLog('[-] There was an error installing hackTricks. Error: ' + str(e))

# Install Bloodhound
def installBloodhound():
    writeToLog('[*] Finding latest Blood Hound Release.')
    try:
        latestLinkPage  = get('https://github.com/BloodHoundAD/BloodHound/releases/latest').text.splitlines()
        latestBloodHoundZip = [match for match in latestLinkPage if "BloodHound-linux-x64.zip" in match][0].split('"')[1]
        writeToLog('[+] latest Blood Hound Zip at: ' + latestBloodHoundZip)
    except Exception as e:
        writeToLog('[-] latest Blood Hound Zip not found. Error: ' + str(e))
        return
    writeToLog('[*] Installing Bloodhound...')
    try:
        run(['/usr/bin/curl -Lo /tmp/bloodhound.zip https://github.com' + latestBloodHoundZip],shell=True)
        run(['/usr/bin/unzip -o /tmp/bloodhound.zip -d /opt/'],shell=True)
        run(['/usr/bin/ln -sf /opt/BloodHound-linux-x64/BloodHound /usr/local/bin/BloodHound'], shell=True)
    except Exception as e:
        writeToLog('[-] Bloodhound not installed. Error: ' + str(e))

# Find and install latest Zaproxy
def installZaproxy():
    writeToLog('[*] Finding latest Zaproxy Release.')
    try:
        latestLinkPage  = get('https://github.com/zaproxy/zaproxy/releases/latest').text.splitlines()
        latestZapDeb = [match for match in latestLinkPage if "_all.deb" in match][0].split('"')[1]
        writeToLog('[+] latest Zaproxy Zip at: ' + latestZapDeb)
    except Exception as e:
        writeToLog('[-] latest Zaproxy Zip not found. Error: ' + str(e))
        return
    writeToLog('[*] Installing Zaproxy...')
    try:
        run(['/usr/bin/curl -Lo /tmp/zaproxy.deb ' + latestZapDeb],shell=True)
        run(['/usr/bin/dpkg -i /tmp/zaproxy.deb'],shell=True)
    except Exception as e:
        writeToLog('[-] Zaproxy not installed. Error: ' + str(e))


# display log
def displayLog():
    print('[*] The following activities were logged:\n')
    with open(LOG,'r') as log:
        allLines = log.readlines()
        for line in allLines:
            print(line.strip())

# display message for finish line
def giveUserNextSteps():
    print(GREEN + '[+]' + '-----------------------------------------------------------------------------------' + NOCOLOR)
    print(GREEN + '[+]' + '------------------------ ! Script Complete ! --------------------------------------' + NOCOLOR)
    print('\n\n[!] REBOOT the system.')
    nullInput = input('Hit Enter.')

# Re-enable unattended upgrade
    #Only needed if auto kill of unattended upgrades is added

def main():
    checkIfRoot()
    checkForInternet()
    initNotice()
    informAboutUnattendedUpgade()
    createhxhBl00dlustDir(hxhBl00dlust_DIR)
    startLogFile()
    freeSpaceStart()
    updateOS()
    installStarterPackages()
    installAPTandSNAPPackages()
    swapNetcat()
    installMSF()
    installWordlists()
    installExploitDb()
    installImpacket()
    installEnum()
    installEnumNG()
    installWebShells()
    installWindowsResources()
    installBloodhound()
    feroxBuster()
    corsy()
    theHarvestor()
    hackTricks()
    freeSpaceEnd()
    displayLog()
    giveUserNextSteps()
    exit(0)

main()
if __name__== "__main__":
    main()
