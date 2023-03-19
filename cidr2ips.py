#!/usr/bin/env python3
"""Turns any CIDR networks provided on stdin into individual IP addresses.  Works for both ipv4 and ipv6."""

#Copyright William Stearns <william.l.stearns@gmail.com>
#Released under the GPL.


import ipaddress
import sys

cidr2ips_version = '0.3'

Devel = True


def Debug(DebugStr):
	"""Prints a note to stderr"""

	if Devel:
		sys.stderr.write(DebugStr + '\n')

AllSucceeded = True

for InLine in sys.stdin:
	InLine = InLine.rstrip('\n')
	#Debug(InLine)
	net = None
	try:
		net = ipaddress.ip_network(InLine, strict=False)
	except ValueError:
		AllSucceeded = False

	if net:
		for Address in net:
			print(Address)


if not AllSucceeded:
	Debug('One or more input lines were not recognized as cidr networks or hosts')
