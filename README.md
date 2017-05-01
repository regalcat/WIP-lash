# WIP-lash
A Wireless Intrusion Detection (and Prevention) project written in Python (3.4)

## DISCLAIMER
This program was written for Python 3.4 so running it with 2.7 may cause issues.
I honestly haven't tested that. You must have a network card that supports 
monitor mode for this software to work. Some results are dependent on the
chipset and 

This software is a proof of concept. The author provides no guarantees that it
will detect 100% of deauth attacks.

## Requirements
The requirements are as follows:
 - scapy
 - argparse

## Usage
NOTE: If you are on Linux, check to make sure the script is set as executable.
The basic usage is: ./wip-lash.py interface mode

The two modes are 'deauth' and 'tracker'.

For a full listing of options, run the program with the -h or --help flags.
