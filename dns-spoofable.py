import argparse
import socket
import sys
import signal
import wget
import os
import time

from threading import Thread
from scapy.all import *
from pathlib import Path

parser = argparse.ArgumentParser (
    description="DNS Spoofable Servers: A tool to get all UDP spoofable servers from the public DNS domain"
)

parser.add_argument("-o", "--output", default='spoofable_dns.txt', help="Filename to store the spoofable servers in")

args = parser.parse_args()

if len(sys.argv) <= 1:
    parser.print_help()
    sys.exit(1)


dns_list = []
threadRun = True
dnsCount = 0

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def getDNSServers():
    global maxThreads
    global threadCount

    print('Downloading dns server list...' )
    url = 'https://public-dns.info/nameservers.txt'
    filename = 'nameservers.txt'

    if (Path(filename).is_file()):
        os.remove(filename)

    wget.download(url)

    print('\r\nLoading list into memory...')
    with open(filename) as file:
        dns_list = [line.rstrip() for line in file]

    for i in dns_list:
        if (validate_ip(i)):
            _ = Thread(target=testDNSServer, args=(i,)).start()

def testDNSServer(ip):
    try:
        dns_request = IP(dst=str(ip)) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='google.com', qtype='SOA'))
        response = sr(dns_request, timeout=1, verbose=False)

        if ('UDP:1' in str(response[0])):
            with open(args.output, "a") as f:
                f.write(str(ip) + '\n')
        
    except socket.error as e:
        print("Socket: ", e)
    except Exception as e:
        print("Exception: ", e)

def signal_event_exit(signal, frame):
    global threadRun
    threadRun = False
    sys.exit(0)

if __name__ == "__main__":
    parser.print_help()

    signal.signal(signal.SIGINT, signal_event_exit)
    
    if (Path(args.output).is_file()):
        os.remove(args.output)

    getDNSServers()
    
    print('Operation complete. DNS Spoofable servers: ', dnsCount)
