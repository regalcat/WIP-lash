#!/usr/bin/python3

import socket
import argparse
import netifaces
import os
import curses
import struct

#-----------------
#- WIP-lash v0.1 -
#-----------------

# @author Steff Bisinger
# @description A wireless security measure that can warn of wireless attacks

# Global defaults
verbose=False

# This function does all the setup and contains the main loop at the moment
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface",help="The interface the program should use")
    # TODO: Actually do curses things when this is set
    #parser.add_argument("-i","--interactive",help="Turn on interactive mode and start the GUI")
    #parser.add_argument("-n","--network",help="The network to be monitored")
    parser.add_argument("-v","--verbose",help="Sets the verbosity to 'loud'")
    arguments = parser.parse_args()
    
    if arguments.verbose:
        global verbose
        verbose=True

    print("Starting packet capture on interface {}".format(arguments.interface))
    # Create the raw socket
    try:
        iface = socket.socket(socket.AF_LINK,socket.SOCK_RAW)
        mac = get_mac(arguments.interface)
        # Ask for the networks to be monitored
        #try:
        #    networks = os.system("iwlist " + args.interface + " scan");
        #    print(getnets(networks))
        #except:
        #    print("Could not get network list. Interface doesn't support scanning.")
        nets = input("Which networks would you like to monitor?: ")
        nets = nets.split()
        iface.bind(mac,0)

        print("Initiating wireless intrusion detection on interface {}".format(arguments.interface))
        # Do the 'D' and 'P' parts of WIDS and WIPS here
        # Might want multiple threads here in the future
        # Especially if the monitor function takes a while
        quit = False
        while(not quit):
            # Receive the packet
            packet = iface.recvfrom(65565)
            # Process the packet
            if(args.network):
                verdict = monitor(packet)
            else:
                verdict = monitor(packet, args.v)
            # Taste the packet
            if verdict[0]:
                print("A deauth was detected.")
                print("Reason: {}".format(verdict[1]))
                print("Flags: {}".format(verdict[2]))
                print("Checksum: {}".format(verdict[3]))
                print("Timestamp (UTC): {}".format(verdict[4]))
                # If the 


    except:
        print("Cannot create socket")


# Gets the MAC address of the specified interface
def get_mac(ifname):
    addrs = netifaces.ifaddresses(ifname)
    macs = addrs[netifaces.AF_LINK]
    return macs[0].get('addr')

# Parses a list of APs with info and returns a list of tuples with the name and 
# other useful info
#def getnets(net_dict):
    # TODO

# Detects deauth packets
# Inputs: pkt: the packet to be looked at
#    net: the MAC address of the network we want to monitor
# Returns a tuple
def monitor(packet, net=None):
    # Get the timestamp
    timestamp = time.now()
    # Chop the packet into sushi
    pkt = packet[0]
    radiotap = pkt[0:25]
    ieee80211 = pkt[26:49]
    data = pkt[50:]
    wifihdr = unpack('!BBH6s6s6sH',ieee80211)
    # Check if the packet-sushi is not a deauth packet
    typeSubtype = wifihdr[0]
    subtype = typeSubtype >> 4
    if not (subtype==12):
        return [False]
    # Check if it's aimed at our network
    
    if net!=None:
        return [False]
    
    sushi = unpack('!HI',data)
    reason = sushi[0]
    chksum = sushi[1]

    if reason==1:
        reason = "Unspecified reason"
    if reason==2:
        reason = "Previous authentication no longer valid (Severity: Note?)"
    if reason==3:
        reason = "Sending STA is leaving or has left (Severity: Note?)"
    if reason==6:
        reason = "Class 2 frame from nonassociated STA"
    if reason==7:
        reason = "Class 3 frame from nonassociated STA"
    if reason==10:
        reason = "Info in the Power Capability element is unacceptable (Severity: Note?)"
    # TODO - Add 'or checksum is bad'
    if(verbose or flags==0x00):
        return [True, reason, flags, chksum, timestamp]
    # Or if it's a disassociate
    

if __name__ == '__main__':
    main()
