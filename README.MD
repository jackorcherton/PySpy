Welcome to PySpy
---------
This is the main project - all the python files are dependancies which are imported into PySpy - so to run the program click on PySpy. The aim of this project is that it will create a simple network enumeration device - that will run on a Beagle Bone Black (running a Debian based Linux distro).
This should also work on the Raspberry Pi & other debian-based Linux Distrabutios.
As well as this we have setup a reverse SSH server - so that the BBB will respond from anywhere with an internet connection - however, you will need a server with a static IP or a service like dyn-dns/no-ip & port forwarding.
Below lists the main features so far, & reasoning behind them:

ARP Scan
---------
The ARP scan was the first project completed (by Jack Orcherton).
The main features of this tool are:
1. IP Discovery - Finds Your Current IP Address & the Subnet you are on.
   - Saves human's having to enter and find out IP info - removes chance of person typing it wrong (human error)
   - Helps automate the project more
   - Done by pinging Google DNS, then inspecting the packet recieved for your IP address (tried originally to try and find this information from the host - but would only return loopback address) - this feature will only work with an external internet connection.
    - If IP discovery fails - it will prompt you to enter your IP
2. Scan the subnet of the network you are on.
    - This is done via ARP scanning
    - Chosen over ping sweep as some devices are able to ignore ICMP requests (e.g. if the device is in promiscious mode) - whereas they are unable to ignore ARP requests
3. Display results in a table - works out the IP address, MAC address & the device creator.
    - Helps to find the layout of the network & what devices are used.
5. Save results to a database.
    - Helps towards automation - results can be saved & accessed at a later date
6. Each time it is run the database is updated/new entries are added.
    - Helps towards automation - overtime results can be used to work out what IP's the dhcp server gives out and build a picture of the network overtime

ARP Spoofing
---------
Third Project by Jack Orcherton
ARP spoofing is a type of man-in-the-middle attack, which if successful means that the target system will send all the data to the attacker & the default gateway (typically a router) will send all the data destined for the target to the attacker.
The point of this is that in corporate networks switches are used & will typically send the data directly to it's destination - meaning that other devices on the network cannot 'inspect' this traffic. With ARP spoofing, it will allow the attacker to just get the target system to send all the data to itself - therefore ignoring the switch problem.
Main Features:
1. Retrieve all previosly seen devices & allow the user to set the target & default gateway
2. ARP Spoof

MAC Address Finder
---------
Project by Jack Orcherton
This allows the user to find who made the device, when given the MAC address. This can then be used to target exploits related to that manufacturer. For example if you saw a Cisco device you could try using the CVE-2019-12669 vulnerability.
A disadvantage to this project is that some operating systems implement MAC address randomisation - the downside to this is that it could lead to false positives in results. Example of OS's that support this:
1. Windows - not turned on by default
2. Android - turned on by default from version 10
3. iOS - turned on by default from version 8
4. OSx - not possible

NB: server's generally don't change MAC addresses - as the MAC is used for DHCP IP reservations.

Network Sniffer
---------
Project by Jack Orcherton & Mamadu Djalo
Used to capture network traffic - this can be useful for information when it is sent in plain text. Currently supports the following protocols:
1. DNS
   - Able to view all DNS queries & responses (therefore we can track websites visited by each client)
   - DNS is historically sent unencrypted - however efforts have been made to use encrypted versions, which we can't intercept - like DNS-over-HTTPS & DNS-over-TLS - this is a relatively new concept - the follow browsers support it:
	- Chrome - No support (under-development)
   	- Firefox - Full Support -enabled by default in US (have to manually enable it everywhere else)
   	- Edge/Explorer - No support (under-development for Edge)
2. HTTP
   - Able to view any HTTP connection
   - Can view post requests - so able to intercept user names and passwords sent in clear text
   
 All results are saved in a database for automation purposes.
 NB - will only work with ARP spoofing on modern switch networks - otherwise will work fine on WiFi & hub based networks.
 Mamadu is currently looking at supporting additional protocals
 
 Reverse SSH
 ---------
 Project by Jack Orcherton (BeagleBone & SSH setup) & Jordan (Microsoft Azure Server & Static IP setup)
 As we do not know which IP will be assigned to the BeagleBone, we have setup a reverse shell for the BBB. As well as this, most firewalls will block incomming SSH traffic by default. This will allow us to be able to control the BBB from anywhere.
 
 File Server
 ---------
 Project by Jack Orcherton. As the above program saves the results from the ARP scan & packet sniffer to the database - we needed a means to transfer the database from the Beaglebone to the Ubuntu Server. To do this, I thought of the following ways:
 1. SCP - a command that can be used for retrieving files through SSH.
 2. FTP - a protocol specifically designed for transfering files
 3. HTTP - protocol for sending webpages over the internet - but can also be used to transfer files.
 
 In the end, I decided to use HTTP this is because the other protocols aren't always seen on all networks & therefore may be picked up, or even blocked by network administrators, whereas everyone uses web traffic - therefore it looks less suspicious. To setup the server I decided to use the simpleHTTPserver module in Python - however, a downside to this is that by default it automatically displays and allows anyone to download the files in the directory it is running - I decided to remove this feature by uploading a web page over the top - https://error404coventry.hopto.org/. As well as this, the server will allow anyone to upload files (as we do not know what the IP of the BeagleBone will be. In order to minimise the risk of just anyone uploading a file, the file has to be called 'info.sqlite3' otherwise the file is rejected.
 
 A downside to HTTP, is that it is unencrypted - therefore if a network admin did inspect the individual HTTP packets, he would be able to view & reconstruct the data sent (and may be able to relise what we are doing) - therefore I decided to use HTTPS, the encrypted version of HTTP - so if someone looked at the packet - they cannot view the data inside.
 
 It has all been encrypted by using a signed TLS 1.3 certificate from the certificate agency letsencrypt.

Finally, I have scheduled a crontab job that runs with root privlages (so that the server can bind to the HTTPS port 443) that will start the server automatically when Ubuntu is rebooted - using crontabs (type command sudo crontab -e, then enter '@reboot python3 /path/to/script.py. The database will be saved in the /root directory.

Database Upload
 ---------
Project by Jack Orcherton - simple python script that will upload the database to the file server - can be called anytime using the PySpy main program, and also set as a crontab job to run automatically @ 1am everyday. To setup - type crontab -e then add the following: 0 1 * * * python3 /path/to/script.py
To change this to upload it to your server, you need to change line 9 of dbUpload.py to your domain.

TCP Scan
---------
Project by Jack Orcherton - a python script which will retrieve previous addresses found by the ARP scan, and will then prompt the user to select one. The program will then attempt to 'ping' the device. It will then ask the user whether they would like to scan in the following modes:
1. TCP scan of the top 20 most frequently opened ports
2. Scan of the well-known ports (1-1024)
3. Custom Range Scan (any port between 1-65535)
The results will then be displayed to the end user & saved to the database

I have chosen to use a TCP scan, instead of a stealth scan, as because the BBB will be on the companies network - traffic will be less likely to be suspected coming from an 'internal' network device. As well as this, this type of scan would be a lot quicker compared to a stealth scan.

UDP Scan
---------
Project by Mark Finta - a python script which will retrieve previous addresses found by the ARP scan, and will then prompt the user to select one. The program will then attempt to 'ping' the device. It will then ask the user whether they would like to scan in the following modes:
1. TCP scan of the top 20 most frequently opened ports
2. Scan of the well-known ports (1-1024)
3. Custom Range Scan (any port between 1-65535)
The results will then be displayed to the end user & saved to the database

Dependancies
-------------------------
Python 3.8+ (should work with any interpreter in the 3.x branch)
PyShark (Type 'python3 -m pip install PyShark' - sometimes you need to remove the '3' - required for the packet capture on the BBB)
Server/Static IP for the Web Server (for database sync)
Let's Encrypt Free SSL Certificate (allows for HTTPS encrypted data transfer)

Legal
-------------------------
PLEASE NOTE - this code is only for educational purposes - and does work on a network. Due to what these tools do, please do not run them on any network that you do not have permision too - we accept no liability.