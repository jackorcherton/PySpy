#Author: Jack Orcherton
from scapy.all import ARP, Ether, srp
import sqlite3, datetime, socket

def findIP():
    """Finds IP - however will not find real address in VMware NAT mode"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        IP=(s.getsockname()[0])
        IP=IP.split(".")
        IP=IP[0]+"."+IP[1]+"."+IP[2]+".1/24"
        print(IP)
    except OSError:
        print("Unable to determine IP. For future double check that you are able to ping external addresses.")
        IP=input("Please enter a target range (for example: 192.168.159.1/24):  ")
    s.close()
    return IP

def macToManDisplay():
    """Used as interface for 'user search' feature on PySpy"""
    print("____________________________________________________\n")
    print("MAC to Manufacturer Search")
    mac=input("Please enter the MAC address: ")
    match=macToMan(mac)
    print("Range: ", match)

def macToMan(searchInput,searchCount=0):
    """Given a mac, it is matched to a manufacturer"""
    searchInput=searchInput[:8].upper()#Converts input to uppercase & keeps the first 8 characters

    with open("MACvendors.txt", "r") as file: #Opens the text file
        for line in file: #Loops through every line in the document
            if searchInput in line: 
                searchCount+=1
                if searchCount==1:  result=line
                else:
                    result="More than one possible manufacturer found."
                    break            
    if searchCount==0:  result="Unknown Manufacturer"
    return result

def ARPdb(IP,MAC,Vendor,currentTime):
    """Given correct data will save/update the ARP logging table"""
    with sqlite3.connect("info.sqlite3") as db: cursor = db.cursor()#This creates a connection to the database
    try:#If IP hasn't been seen before
        data=[IP,MAC,Vendor,currentTime]
        cursor.execute("insert into ARP (IP, MAC, Vendor, LastSeen) values (?,?,?,?)",data)
    except(sqlite3.IntegrityError):#If IP has been previously captured
        data=[MAC, Vendor, currentTime, IP]
        cursor.execute("UPDATE ARP SET MAC=?,Vendor=?,LastSeen=? WHERE IP=?",data)
    db.commit()
    db.close()

def arpScan():
    """Completes an ARP scan of specified IP range"""
    print("____________________________________________________\n")
    print("ARP Scan\n")
    autoMode=input("Would you like to automatically detect IP subnet? [Y/N]: ")
    if autoMode=="y" or autoMode=="Y":  targetRange=findIP()
    else:   targetRange=input("Please enter a target range (for example: 192.168.159.1/24): ") #Will change to input
    arpRequests=ARP(pdst=targetRange) #create packet for broadcast
    broadcastMAC = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcastMAC/arpRequests #Joins the request & broadcast mac - required for arp

    result = srp(packet, timeout=3, verbose=0)[0]#Sends packets & records result
    discovered = []
    
    #Gathers all responses
    for null, response in result:
        macVendor=macToMan(response.hwsrc).strip("\n")
        discovered.append([response.psrc,response.hwsrc,macVendor[9:]])

    #Displays to user
    currentTime=str(datetime.datetime.now())
    print("Devices Found:")
    print("IP" + " "*15+"MAC"+" "*15+"MAC Vendor")
    for i in range(len(discovered)):
        print("{:16} {:16} {}".format(discovered[i][0],discovered[i][1],discovered[i][2]))
        ARPdb(discovered[i][0],discovered[i][1],discovered[i][2],currentTime)