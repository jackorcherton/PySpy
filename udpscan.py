import ARPresults,datetime,socket,sqlite3,tcpScan
from os import system

def setTarget():
    """Get's user to set target, then select scan type"""
    print("____________________________________________________\nUDP Scan\n")
    custom = input("Would you like to use an IP in the ARP table [Y] or a custom IP [N]? [Y/N]: ")
    if custom == "y" or custom == "Y":
        if ARPresults.fetchARPtable():
            print("s")
            target = ARPresults.getTarget("Please type ID of target: ")
            print(target)
            if target == "No targets found - try running an ARP scan from the main menu":   return
            target = target[0]
        else:
            print("Database cannot be found either try again or use custom mode.")
            return setTarget()
    else:   target = input("Enter target IP: ")
    ping =tcpScan.checkPing(target)
    if ping:   print("Responds to ping\n")
    print("What would you like to do?")
    print("1. Scan Top 20 Most Likely Open Ports")
    print("2. Scan Well Known Ports (Ports 1-1024)")
    print("3. Enter Custom Range (must be between 1 - 65535")
    while (True):
        scanType = input("Enter Type of Scan: ")
        if scanType == "1":
            openPorts = topPortScan(target)
            sql_ports = "INSERT INTO portScan(IP,scanTime,protocol,port,portDescription) VALUES (?,?,?,?,?)"
            break
        elif scanType == "2":
            openPorts = fullScan(target)
            break
        elif scanType == "3":
            startPort, endPort = tcpScan.validatePorts()
            openPorts = fullScan(target, start=startPort, end=endPort)
            break
        else:
            print("That's an invalid option - try again!\n")

    if scanType == "2" or scanType == "3":
        sql_ports = "INSERT INTO portScan(IP,scanTime,protocol,port) VALUES (?,?,?,?)"

    with sqlite3.connect("info.sqlite3") as db:
        cursor = db.cursor()  # This creates a connection to the database
    if ping:
        data = [target, str(datetime.datetime.now()), "ICMP", "Target responds to ping request"]
        cursor.execute("INSERT INTO portScan(IP,scanTime,protocol,portDescription) VALUES (?,?,?,?)", data)
    cursor.executemany(sql_ports, openPorts)
    db.commit()
    db.close()

def portScanner(target, port):
    """This scans the port"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, port))  # Attempts to connect to port
        s.close()  # Closes connection
        return True  # If successful, the port was open
    except:
        return False


def fullScan(target, start=1, end=1024):
    """Given an IP, the address will be scanned for ports 1 tp 65535"""
    openPorts = []
    currentTime = str(datetime.datetime.now())
    print("This will scan all 65535 udp ports... There may a be a wait...")
    for port in range(start, end + 1):
        if portScanner(target, port):
            print(port, "is open")
            openPorts.append((target, currentTime, "UDP", port), )
    return openPorts


def topPortScan(target):
    """Given an IP, scans top 20 used UDP ports"""
    topPorts = {
        21: "FTP (File Transfer Protocol)",
        22: "SSH (Secure Shell)",
        23: "Telnet",
        25: "SMTP (Simple Mail Transfer Protocol)",
        53: "DNS (Domain Name System)",
        80: "HTTP (HyperText Transfer Protocol)",
        110: "POP3 (Post Office Protocol 3)",
        111: "rpcbind",
        135: "MSRPC (Microsoft Remote Procedure Call)",
        139: "netbios-ssn",
        143: "IMAP (Internet Message Access Protocol)",
        443: "HTTPS (HyperText Transfer Protocol Secure)",
        445: "microsoft-ds (Microsoft Directory Services)",
        993: "IMAPS (Internet Message Access Protocol Secure)",
        995: "POP3S (Post Office Protocol 3 Secure)",
        1723: "PPTP (Point-to-Point Tunneling Protocol)",
        3306: "MySQL",
        3389: "RDP (Remote Desktop Protocol)",
        5900: "VNC (Virtual Network Computing)",
        8080: "http-proxy"
    }  # Dictionary of NMap top 20 ports
    openPorts = []
    currentTime = str(datetime.datetime.now())
    print("Scanning... This may take a moment...")
    print("The following ports are open:\n\nPort | Use")
    for port in topPorts:
        if portScanner(target, port):  # Scans each port, if successful, it is displayed in a table
            print("{:<5}  {:<15}".format(port, topPorts[port]))  # Formats table
            openPorts.append((target, currentTime, "UDP", port, topPorts[port]), )
    return openPorts


if __name__ == '__main__':  setTarget()  # If the program isn't being imported - it will automatically run
