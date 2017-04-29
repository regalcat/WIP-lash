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
# Just made of concurrency issues
naughtylist=[]
naughtydicts=[]

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
            'interface' : arguments.interface
            }
    sniffer = SnifferThread(1,"sniffer1",sniffer_args)
    sniffer.start()
    quit=False
    while not quit:
        # This seems like a really stupid way to do this
        # We're missing some serious input sanitation. Gross...
        cmd = input("Enter a command or 'help' for a list of commands: \n")
        if cmd.lower()=="quit":
            print("Exiting normally")
            sys.exit(0)
        elif cmd.lower()=="help":
            print("Command - Description")
            print("quit .......... Terminates the program")
            print("help .......... Prints this list of commands")
            print("add [MAC] ..... Adds the MAC to the list of protected networks")
            print("rm [MAC] ...... Removes the MAC from the list of protected networks")
            print("list nice ..... Lists the networks being protected")
            print("list naughty .. Lists MACs that have sent 'bad' deauth packets")

        #elif cmd.lower()==re.match('add \d\d:\d\d:\d\d:\d\d:\d\d:\d\d',cmd.lower()):
            #TODO
        #elif cmd.lower()==re.match('rm \d\d:\d\d:\d\d:\d\d:\d\d:\d\d',cmd.lower()):
            #TODO
        #elif cmd.lower()=="list nice":
        #    print("Protecting these networks")
        #    for n in nicelist:
        #        print(n)
        #elif cmd.lower()=="list naughty":
        #    print("Gathering intel on these MACs")
        #    print("MAC | Sig Str | Target | Probes")
            # Probably a concurrency issue
        #    for n in naughtydicts:
        #        print("{} | {} | {} | {}".format(n.mac,n.sigstr,n.targets,n.probes))
        else:
            print("Sorry, I didn't catch that. Please try again.")


class SnifferThread(threading.Thread):
    def __init__(self, threadId, name, kargs):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.iface = kargs['interface']

    def run(self):
        print("Sniffer thread is running")
        print("Deauth detection initiated!")
        sniff(iface=self.iface, prn=PacketHandler)

# This needs to be as lean as possible
# Yeah, Steff. That'll happen
def PacketHandler(pkt):
    global counter
    counter+=1
    if pkt.haslayer(Dot11):
        if pkt.type==0 and pkt.subtype==12:
            global nicelist
            if (pkt.addr1 in nicelist) or (pkt.addr2 in nicelist) or verbose:
                # Probably concurrency issues here
                #global naughtylist
                #if pkt.addr1.lower() in naughtylist:
                    
                #else:

                print("Deauth: {} -> {} Flags: {} Reason: {}".format(pkt.addr1,pkt.addr2,pkt.flags,pkt[Dot11Deauth].reason))
        #elif pkt.


if __name__ == '__main__':
    main()
