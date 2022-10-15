#! /usr/bin/env python3

import scapy.config
import scapy.route
import scapy.layers.l2
import math
import socket
import os
import sys

def host_identifier(netmask):
    return 32 - int(round(math.log(0xFFFFFFFF - netmask, 2)))

def cidr_notation(network, netmask):
    # Classless inter-domain routing (CIDR) is a set of Internet protocol (IP) standards
    # that is used to create unique identifiers for networks and individual devices.
    #
    # CIDR IP addresses consist of two groups of numbers, the most important of these groups
    # is the network address, and it is used to identify a network or a sub-network (subnet).
    # The lesser of the bit groups is the host identifier. The host identifier is used to
    # determine which host or device on the network should receive incoming information packets.
    network = scapy.utils.ltoa(network)
    netmask = host_identifier(netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16: return
    return net

def arping(ip, interface):
    if ip:
        print("arping to ip %s on interface %s" % (ip, interface))
        ans, _ = scapy.layers.l2.arping(ip, iface=interface, timeout=2, verbose=1)
        for _, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                pass
            print(line)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print('Need root to run this script', file=sys.stderr)
        sys.exit(1)

    # https://scapy.readthedocs.io/en/latest/routing.html
    print(scapy.config.conf.route)

    for network, netmask, gateway, interface, output_ip, metric in scapy.config.conf.route.routes:
        if network <= 0 or interface == 'lo' or output_ip == '127.0.0.1' or output_ip == '0.0.0.0' or netmask == 0xFFFFFFFF or netmask >= 0xFFFFFFFF:
            # skip network and default gateway
            continue

        arping(cidr_notation(network, netmask), interface)

