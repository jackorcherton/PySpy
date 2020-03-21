#Author: Jack Orcherton
import arpScan, sqlite3, networkSniffer, arpSpoof, dbUpload, tcpScan, udpscan

def dbSetup():
    """Ensure's database exists, if not new one is created"""
    with sqlite3.connect("info.sqlite3") as db: cursor = db.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS ARP(ID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, IP TEXT NOT NULL UNIQUE,MAC TEXT NOT NULL, Vendor TEXT NOT NULL, LastSeen TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS DNS(ID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, IP TEXT,Type TEXT,queryName TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS HTTP(ID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,fullURL TEXT,IP_Source TEXT,requestType TEXT,userAgent TEXT,data TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS portScan(ID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,IP TEXT,scanTime TEXT,protocol TEXT,port INTEGER,portDescription TEXT)')
    db.close()

def banner():
    print("____________________________________________________\n\nError 404 are proud to present PySpy!\n")
    print("                         %\n                      %%%%%%#\n                   (%%%%  ,%%%%.\n                 %%%%%%%%%%%%%%%%% ")
    print("              %%%%%%%%&*   /%%%%%%%%,\n           .%%%%%                .%%%%%\n         %%%%%    ,%%%%%%%%%%%%      %%%%(")
    print("      ,%%%%,   .%%%%%       .%%%%%/    (%%%%\n    %%%%%    %%%%%     %%       #%%%%     %%%%%\n /%%%%.%%%%%%%%.     %%%*          %%%%#    *%%%%.")
    print(",%%%%    *%%%%.     *%%%%%(,/%      %%%%%%.  *%%%%\n   %%%%%    %%%%&     %%%%%%%    #%%%%  %%%%%%%%\n     ,%%%%.   .%%%%%          .%%%%/    (%%%%")
    print("        %%%%%    .%%%%%%%%%%%%%%%     %%%%(\n          .%%%%%       *(((*       %%%%%\n             #%%%%%%          .%%%%%%*\n                %%%%%%%%%%%%%%%%%%%")
    print("                  (%%%%    ,%%%%.\n                     %%%%%%%%%\n                       /%%%.\n\nNetwork Enumeration suite\n____________________________________________________\n")
    menu()

def menu():
    """Main Menu for program"""
    print("Navigation tip - press ctrl + c at anytime to return to the following menu!\n")
    print("PySpy with my little eye something beginning with:")
    print("1. ARP Scan")
    print("2. ARP Spoof")
    print("3. MAC to Manufacturer Search")
    print("4. Network Sniffer - Captures DNS & HTTP")
    print("5. TCP Scan")
    print("6. UDP Scan")
    print("7. Upload Database to Server")
    print("8. Exit")

    option=input("Please chose an option: ")
    if option=="1": arpScan.arpScan()
    elif option=="2":   arpSpoof.selectTarget()
    elif option=="3":   arpScan.macToManDisplay()
    elif option=="4":   networkSniffer.sniff()
    elif option=="5":   tcpScan.setTarget()
    elif option=="6":   udpscan.setTarget()
    elif option=="7":   dbUpload.send()
    elif option=="8":   exit("Goodbye")
    else:
        print("Not an option! Please try again!\n")
        menu()

dbSetup()
while(True):
    try:   banner()
    except KeyboardInterrupt:
        print("\n\nReturning you to the main menu - type 7 to exit.\n")
        pass
    except EOFError:
        print("It happened")
        pass