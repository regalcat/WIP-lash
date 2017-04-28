#!/usr/bin/python3

import threading
import re
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
counter=0
nicelist=[]

# This function does all the setup and contains the main loop at the moment
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface",help="The interface the program should use")
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
                interface = arguments.interface
            }
    sniffer = SnifferThread(1,"sniffer1",sniffer_args)
    sniffer.start()
    quit=False
    while not quit:
        cmd = input("Enter a command or help for a list of commands: \n")
        if cmd.lower()=="quit":
            print("Exiting normally")
            sys.exit(0)
        elif cmd.lower()=="help":
            print("Command - Description")
            print("quit ..... Terminates the program")
            print("help ..... Prints this list of commands")

        elif cmd.lower()==re.match('',cmd.lower())


class SnifferThread(threading.Thread):
    def __init__(self, threadId, name, kargs):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.iface = kargs.interface

    def run(self):
        print("Sniffer thread is running")
        sniff(iface=self.iface, prn=PacketHandler)

def PacketHandler(pkt):
    global counter
    counter+=1
    if pkt.haslayer(Dot11):
        if pkt.type==0 and pkt.subtype==12:
            if pkt.flags==0 or verbose: #TODO check the checksum
                print("Deauth packet detected: %s -> %s Flags: %s" %(pkt.addr1,pkt.addr2,pkt.flags))


if __name__ == '__main__':
    main()
