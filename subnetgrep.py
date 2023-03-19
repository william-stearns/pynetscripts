#!/usr/bin/env python3
"""Takes lines containing IP addresses on stdin.  If they're in one or more of the command-line-or-file-supplied subnets, spit the entire line to stdout."""

#Copyright 2016-2018 William Stearns <william.l.stearns@gmail.com>
#Released under the GPL


__version__ = '0.18'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2016-2023, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Production'				#Prototype, Development or Production



#Tcpdump processing sample; source IP:
#	tcpdump -qtnp  | subnetgrep.py -t '[ >]+' -k 2 -s 204.0.0.0/8 2001::/16
#Tcpdump processing sample; dest IP:
#	tcpdump -qtnp  | subnetgrep.py -t '[ >]+' -k 3 -s 204.0.0.0/8 2001::/16
#Passer sample:
#	cat passer-log | subnetgrep.py -t , -k 2 204.0.0.0/8 2001::/16


#======== External libraries
import re				#Process regular expressions
import os				#File access
import sys				#Used for reading from stdin/writing to stdout
from typing import Dict, List, Union
try:
	import ipaddress		#IP address/network objects and functions
except ImportError:
	print("Missing ipaddress module; perhaps 'sudo port install py-ipaddress' or 'sudo -H pip install ipaddress' ?  Exiting.")
	raise


#======== Global variables
TestObjects: List[str] = []		#Raw subnet strings that will later be loaded as IP objects into FilterNetworks
FilterNetworks: Dict[str , List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = {}		#Dictionary of arrays: Keys are the first "octet" of the address, Values are an array of Networks that we must match

Devel = True


#======== Functions
def Debug(DebugStr: str) -> None:
	"""Prints a note to stderr"""

	if Devel:
		sys.stderr.write(DebugStr + '\n')


def MakeUnicode(raw_string: Union[bytes, str]) -> str:
	"""Return a unicode string whether we're on python 2 or python 3."""

	try:
		if sys.version_info > (3, 0):
			unicode_string = str(raw_string)
		else:
			unicode_string = unicode(raw_string)						# pylint: disable=undefined-variable
	except UnicodeDecodeError:
		unicode_string = ''

	return unicode_string


def LoadFilterNets(TestObjs: List[str]) -> Dict[str , List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
	'''Load possible subnets into FilterNetworks'''

	FilterNets: Dict[str , List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = {}		#Dictionary of arrays: Keys are the first "octet" of the address, Values are an array of Networks that we must match
	SubNewSubnet: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

	for IPObj in TestObjs:
	#Put into "first octet" buckets (for ipv6, use the 4 hex digits preceding the first colon)
		LeadingOctet: str = IPObj.split('.')[0].split(':')[0]
		NewSubnet: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(MakeUnicode(IPObj), strict=False)

		if NewSubnet.version == 4:
			PrefixLimit = 8
		elif NewSubnet.version == 6:
			PrefixLimit = 16
		else:
			Debug('Non-ipv4/ipv6 subnet: ' + str(NewSubnet))
			sys.exit(1)

		if NewSubnet.prefixlen < PrefixLimit:
			#If we get any subnets bigger than /8 (/16 for ipv6), we need to chop them up into /8's or /16's.
			Slash8s: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = list(NewSubnet.subnets(new_prefix=PrefixLimit))
			for SubIPObj in Slash8s:
				SubFirstOctet = str(SubIPObj).split('.')[0].split(':')[0]		# pylint: disable=use-maxsplit-arg
				SubNewSubnet = ipaddress.ip_network(SubIPObj, strict=False)
				if SubFirstOctet not in FilterNets:
					FilterNets[SubFirstOctet] = []
				if not SubNewSubnet in FilterNets[SubFirstOctet]:
					FilterNets[SubFirstOctet].append(SubNewSubnet)
		else:
			if LeadingOctet not in FilterNets:
				FilterNets[LeadingOctet] = []
			if NewSubnet not in FilterNets[LeadingOctet]:
				FilterNets[LeadingOctet].append(NewSubnet)

	return FilterNets


def InFilterNetworks(raw_IP: str, FilterNets: Dict[str , List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]) -> bool:
	"""Returns True if the supplied IP address is in one of the filter networks; False otherwise"""

	if "InNetworkCache" not in InFilterNetworks.__dict__:
		InFilterNetworks.InNetworkCache = {}							# type: ignore	#Keys are IP addresses, value is True or False.

	IP: str = MakeUnicode(raw_IP)

	if not IP:
		IsInFilterNetworks =  False
	elif IP in InFilterNetworks.InNetworkCache:							# type: ignore
		IsInFilterNetworks = InFilterNetworks.InNetworkCache[IP]				# type: ignore
	else:
		IsInFilterNetworks = False
		FirstOctet = IP.split('.')[0].split(':')[0]

		IPObject = None

		try:
			IPObject = ipaddress.ip_address(IP)
		except ValueError:
			#See if it's in 2.6.0.0.9.0.0.0.5.3.0.1.B.7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 or 260090005301B7000000000000000001 format
			hex_string = IP.replace('.', '')
			colon_hex_string = hex_string[0:4] + ':' + hex_string[4:8] + ':' + hex_string[8:12] + ':' + hex_string[12:16] + ':' + hex_string[16:20] + ':' + hex_string[20:24] + ':' + hex_string[24:28] + ':' + hex_string[28:32]
			FirstOctet = hex_string[0:4]
			try:
				IPObject = ipaddress.ip_address(colon_hex_string)
			except ValueError:
				Debug(str(IP)+' not an address')
				return False
		except:											# pylint: disable=bare-except
			Debug('Some other error loading ' + IP)
			return False


		if IPObject:
			if FirstOctet in FilterNets:
				for OneNet in FilterNets[FirstOctet]:
					if IPObject in OneNet:
						IsInFilterNetworks = True
						break
			#Following 2 lines not needed as "False" is the default for this variable
			#else:
			#	IsInFilterNetworks = False

			InFilterNetworks.InNetworkCache[IP] = IsInFilterNetworks			# type: ignore

	return IsInFilterNetworks


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='subnetgrep.py version ' + str(__version__) + ': a filter that only returns lines containing addresses that match a subnet.')
	parser.add_argument('-v', '--invert', help='Invert test; only show lines that do NOT match any of the supplied subnets.', required=False, default=False, action='store_true')
	parser.add_argument('-k', '--field', help="Which field of stdin contains the IP address.  First field is numbered 1 to match sort's usage.", required=False, default=1, type=int)
	parser.add_argument('-f', '--subnetfile', help='read subnets from this file.', required=False, default=None)
	parser.add_argument('-s', '--striptcpdumpport', help='Strip tcpdump port from the IP address before using.', required=False, default=False, action='store_true')
	parser.add_argument('-t', '--separatorchar', help='character that separates fields on input.', required=False, default='[ \t\n]+')
	parser.add_argument('subnets', help='more subnets to match', default=[], nargs='*')
	args = vars(parser.parse_args())

	Invert: bool = args['invert']
	StripTcpdumpPort: bool = args['striptcpdumpport']
	Separator: str = args['separatorchar']
	FieldNumber: int = args['field'] - 1
	if FieldNumber == -1:
		FieldNumber = 0

	if args['subnetfile']:
		if os.path.exists(args['subnetfile']):
			try:
				with open(args['subnetfile'], 'r', encoding="utf8") as SFHandle:
					for Line in SFHandle:
						if str(Line).rstrip() not in TestObjects:
							TestObjects.append(str(Line).rstrip())
			except:										# pylint: disable=bare-except
				Debug('Unable to read from ' + args['subnetfile'] + ' for some reason, skipping.')
		else:
			Debug('Requested file ' + args['subnetfile'] + ' is not a file, exiting.')
			sys.exit(1)

	for one_subnet in args['subnets']:
		if not one_subnet in TestObjects:
			TestObjects.append(one_subnet)

	if len(TestObjects) == 0:
		if Invert:
			Debug('Note, no subnets supplied, so all lines will be output as -v/Invert requested.')
		else:
			Debug('Note, no subnets supplied, so no lines will be output.')

	#Load up the list of networks objects from the supplied filter strings
	FilterNetworks = LoadFilterNets(TestObjects)


	MissingFieldWarning: str = ''

	#Read input lines; if IP address matches one of the subnets, output it
	for InLine in sys.stdin:
		IPAddress = ''

		try:
			if sys.version_info > (3, 0):
				IPAddress = re.split(Separator, InLine)[FieldNumber]
			else:
				#filter returns a list in python2
				IPAddress = filter(None, re.split(Separator, InLine))[FieldNumber]	# pylint: disable=unsubscriptable-object
		except:											# pylint: disable=bare-except
			MissingFieldWarning = 'One or more lines did not have field ' + str(FieldNumber) + '\n'

		#Debug(IPAddress)

		#IPAddress = InLine.replace('\n', '')

		#IPSearch = re.search('^..,([^,]*),', InLine.replace('\n', ''))
		#if IPSearch:
		#	IPAddress = IPSearch.group(1)

		if IPAddress:
			if StripTcpdumpPort:
				if FieldNumber == 2:
					IPAddress = re.sub(r':$', r'', IPAddress)
				IPAddress = re.sub(r'^([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*)\.[0-9][0-9]*$', r'\1', IPAddress)
				IPAddress = re.sub(r'^([0-9a-fA-F]*:[0-9a-fA-F:]*)\.[0-9][0-9]*$', r'\1', IPAddress)

			if InFilterNetworks(str(IPAddress), FilterNetworks) ^ Invert:
				sys.stdout.write(InLine)
			#else:
			#	sys.stderr.write('.')

		else:
			sys.stderr.write('Unable to find IP address in InLine\n')

	if MissingFieldWarning:
		sys.stderr.write(MissingFieldWarning)
