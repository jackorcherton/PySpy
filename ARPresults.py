#Author: Jack Orcherton
#This file is used in target selection for ARP spoofing & packet sniffer
import sqlite3

def fetchARPtable():
    """Fetches the ARP scan results to retrive target info"""
    with sqlite3.connect("info.sqlite3") as db: cursor = db.cursor()#This creates a connection to the database
    cursor.execute("SELECT * FROM ARP")
    allTargets=cursor.fetchall()
    db.close()
    if allTargets==[]:
        print("No targets found - try running an ARP scan from the main menu")
        return False
    print("{:4} {:16} {:17} {:26} {}".format("ID","IP Address","MAC Address","Manufacturer","Last Seen"))
    for target in allTargets:  print("{:4} {:16} {:16} {:25} {}".format(target[0],target[1],target[2],target[3],target[4]))
    print()
    return True

def checkTarget(ID):
    """Give ID for target, ensures the ID exists"""
    with sqlite3.connect("info.sqlite3") as db: cursor = db.cursor()#This creates a connection to the database
    cursor.execute("SELECT IP, MAC FROM ARP WHERE ID=?",(ID,))
    targetInfo=cursor.fetchone() #Creates list index 0 = ip, 1 = mac
    if targetInfo==None:    raise ValueError
    return targetInfo

def getTarget(message):
    """Asks user for IP & checks it is in the DB"""
    try:
        targetIP=int(input(message))
        targetIP=checkTarget(targetIP)
        return targetIP
    except ValueError:
        print("You have entered an invalid ID\n")
        cont=input("Would you like to retry [Y/N] ")
        if cont=="y" or cont=="Y":  return getTarget(message)