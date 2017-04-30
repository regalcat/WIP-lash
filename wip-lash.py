#!/usr/bin/python3

import threading
import re
import sched, time
import argparse
import curses
from scapy.all import *

#-----------------
#- WIP-lash v0.1 -
#-----------------

# @author Steff Bisinger
# @description A wireless security measure that can warn of wireless attacks

# Global defaults
verbose=False
quit=False
counter=0
nicelist=[]
sch=sched.scheduler(timefunc=time.time)
threshold=60

# This function does all the setup and contains the main loop at the moment
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface",help="The interface the program should use")
    parser.add_argument("mode",help="The mode to use (deauth and tracker are currently supported)")
    # TODO: Actually do curses things when this is set
    #parser.add_argument("-i","--interactive",help="Turn on interactive mode and start the GUI")
    parser.add_argument("-n","--network",help="The BSSID of the network to be monitored")
    parser.add_argument("-v","--verbose",help="Sets the verbosity to 'loud'")
    arguments = parser.parse_args()
    
    if arguments.verbose:
        global verbose
        verbose=True

    if arguments.network:
        global nicelist
        nicelist.append(arguments.network)

    print("Starting packet capture on interface {}".format(arguments.interface))
    sniffer_args = {
            'interface' : arguments.interface,
            'mode' : arguments.mode.lower()
            }
    sniffer = SnifferThread(1,"sniffer1",sniffer_args)
    sch.enter(1,1,ThresholdChecker)
    sniffer.start()
    sch.run()
    while not quit:
        # This seems like a really stupid way to do this
        # We're missing some serious input sanitation. Gross...
        cmd = input("Enter a command or 'help' for a list of commands: \n")
        if cmd.lower()=="quit":
            print("Exiting normally")
            quit=True
        elif cmd.lower()=="help":
            print("Command - Description")
            print("quit .......... Terminates the program")
            print("help .......... Prints this list of commands")
            #print("add [MAC] ..... Adds the MAC to the list of protected networks")
            #print("rm [MAC] ...... Removes the MAC from the list of protected networks")
            #print("list nice ..... Lists the networks being protected")

        #elif cmd.lower()==re.match('add \d\d:\d\d:\d\d:\d\d:\d\d:\d\d',cmd.lower()):
            #TODO
        #elif cmd.lower()==re.match('rm \d\d:\d\d:\d\d:\d\d:\d\d:\d\d',cmd.lower()):
            #TODO
        #elif cmd.lower()=="list nice":
        #    print("Protecting these networks")
        #    for n in nicelist:
        #        print(n)
        else:
            print("Sorry, I didn't catch that. Please try again.")


class SnifferThread(threading.Thread):
    def __init__(self, threadId, name, kargs):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.iface = kargs['interface']
        self.mode = kargs['mode']

    def run(self):
        print("Sniffer thread is running")
        if self.mode=="tracker":
            print("Activating tracking mode!")
            sniff(iface=self.iface, prn=TrackerHandler)
        elif self.mode=="deauth":
            print("Activating deauth detection!")
            sniff(iface=self.iface, prn=DeauthHandler)
        else:
            print("Invalid mode: '{}'".format(self.mode))

# This needs to be as lean as possible
# Yeah, Steff. That'll happen
# Watches networks on the nice list for deauth packets
def DeauthHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type==0 and pkt.subtype==12:
            global counter
            counter+=1
            global nicelist
            if (pkt.addr1 in nicelist) or (pkt.addr2 in nicelist) or verbose:
                print("Deauth: {} -> {} Flags: {} Reason: {}".format(pkt.addr1,pkt.addr2,pkt.flags,pkt[Dot11Deauth].reason))

# Tracker mode looks at the signal strength of the AP's packets to determine whether its
# identity is being spoofed
# Assumes that neither the AP nor the device running this code is moving
# Future applications: 
def TrackerHandler(pkt):
    if quit:
        sys.exit(0)
    if pkt.haslayer(Dot11):
        if pkt.addr1 in nicelist:
            print("{}'s signal strength is {}".format(pkt.addr1,pkt[RadioTap].dBm_TX_Power))

def ThresholdChecker():
    if quit:
        sys.exit(0)
    if counter>=threshold:
        print("Threshold exceeded! Probable deauth attack!")
    global counter
    counter=0
    sch.enter(1,1,ThresholdChecker)
    sch.run()

if __name__ == '__main__':
    main()
