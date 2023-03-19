#!/usr/bin/env python3
"""Turns any IP addresses provided on stdin into the smallest set of CIDRs for them.  Works for both ipv4 and ipv6."""

#Copyright William Stearns <william.l.stearns@gmail.com>
#Released under the GPL.

#Based on
#https://unix.stackexchange.com/questions/704845/convert-ip-list-to-minimal-cidr-representation

import ipaddress
import sys

cidr2ips_version = '0.3'

Devel = True


def Debug(DebugStr):
	"""Prints a note to stderr"""

	if Devel:
		sys.stderr.write(DebugStr + '\n')

#AllSucceeded = True


all_ips = [ipaddress.ip_address(line.rstrip('\n')) for line in sys.stdin]
print('\n'.join([ip.with_prefixlen for ip in ipaddress.collapse_addresses(all_ips)]))


#for InLine in sys.stdin:
#	InLine = InLine.rstrip('\n')
#	#Debug(InLine)
#	net = None
#	try:
#		new_ip = ipaddress.ip_network(InLine, strict=False)
#	except ValueError:
#		AllSucceeded = False
#
#	if new_ip:
#		for Address in net:
#			print(Address)
#
#
#if not AllSucceeded:
#	Debug('One or more input lines were not recognized as cidr networks or hosts')
