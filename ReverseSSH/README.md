Reverse Shell
-----------------
Allows you to be able to control the BBB from anywhere via ssh.

Dependancies
-------------------------
Python 3.8+ (should work with any interpreter in the 3.x branch)
PyShark (Type 'python3 -m pip install PyShark' - sometimes you need to remove the '3' - required for the packet capture on the BBB)
Server/Static IP for the Web Server (for database sync)
Let's Encrypt Free SSL Certificate (allows for HTTPS encrypted data transfer)

Reverse SSH Setup
---------------------------------------------------------------------------
This script automatically creates a reverse SSH shell to our Azure Server.
It makes use of ssh keys (for authentication), Shell script (for connection script)
& cron jobs for automation (auto run shell script)
---------------------------------------------------------------------------
How to connect:
---------------------------------------------------------------------------
1. Open Terminal (Linux) or CMD (Windows)
2. Type in ssh yourusername@serverIP (so for us it is Jordan@51.143.178.149)
3. Enter Password when prompted
4. Type 'ssh -l <user> -p 2222 localhost' - directs you to the shell on the server
5. Enter BBB password (displayed on screen)
6. You now have SSH access to the BBB :)
---------------------------------------------------------------------------
Initial Deployment (note you should only need to do this once!):
---------------------------------------------------------------------------
1. On BBB type 'ssh-keygen -t rsa' - to create a SSH key
2. On BBB type 'cd ~/.ssh' - to place you in correct directory
3. On BBB type 'scp id_rsa.pub <user>@<server>:.ssh/authorized_keys' - this sends the public key to the server (so for us Jordan@51.143.178.149)
4. On BBB try to connect - so 'ssh <user>@<server>' - if it doesn't work ensure above has been done right
5. On BBB type 'cd ~' - takes back to home directory
6. Copy & paste sshSetup.sh
7. Add execute privlages 'chmod 700 ~/sshSetup.sh'
8. Create a cron job 'cron -e', then copy this to the final line '* * * * * /path/to/sshSetup' - this will attempt to create a connection every minute.
9. Reboot BBB & wait a few mins
10. Go to server - login & type 'ssh -l <user> -p 2222 localhost' (in our case username is debian) - this creates the connection to the BBB
11. Enjoy :)
---------------------------------------------------------------------------
note BBB means BeagleBone Black but above should work on most Linux distro's/computers

Legal
-------------------------
PLEASE NOTE - this code is only for educational purposes - and does work on a network. Due to what these tools do, please do not run them on any network that you do not have permision too - we accept no liability.