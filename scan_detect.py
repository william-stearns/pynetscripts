#!/usr/bin/env python3
"""Listen for packets on an interface and identify Ethernet scanning as might be used by lateral movement and network discovery."""
#Copyright 2023 William Stearns <bill@activecountermeasures.com>

__version__ = '0.3.9'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2023-2024, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'bill@activecountermeasures.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Prototype'				#Prototype, Development or Production


import os
import sys
import tempfile
import gzip												#Lets us read from gzip-compressed pcap files
import bz2												#Lets us read from bzip2-compressed pcap files
from typing import Dict, List, Optional, cast

try:
	#from scapy.all import *
	from scapy.all import sniff, raw, Scapy_Exception, ARP, Ether, ICMP, IP, IPv6, ICMPv6DestUnreach, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6TimeExceeded	# pylint: disable=no-name-in-module,unused-import
	#from scapy.config import conf									#For future use in scapy "conf.use_pcap = True"
except ImportError:
	sys.stderr.write('Unable to load the scapy library.  Perhaps run   sudo apt install python3-pip || (sudo yum install python3-pip ; sudo pip3 install scapy )   ?\n')
	sys.stderr.flush()
	sys.exit(1)


def debug_out(output_string: str):
	"""Send debuging output to stderr."""

	if cl_args['devel']:										# pylint: disable=possibly-used-before-assignment
		sys.stderr.write(output_string + '\n')
		sys.stderr.flush()


def read_list_from_file(filename: str, should_dedup: bool, should_ignore_comments: bool) -> List:
	"""Read individual lines from the named file and assign each one to the entries in the returned list."""

	ret_list = []

	if filename and os.path.exists(filename):
		try:
			with open(filename, 'r', encoding="utf8") as in_h:
				for Line in in_h:
					if (should_dedup and str(Line).rstrip() not in ret_list) or not should_dedup:
						if (not should_ignore_comments) or (not Line.startswith('#')):
							ret_list.append(str(Line).rstrip())
		except:                                                                         	# pylint: disable=bare-except
			debug_out('Unable to read from ' + filename + ' for some reason, skipping.')
	else:
		debug_out('Requested file ' + filename + ' is not a file, exiting.')
		sys.exit(1)

	return ret_list



def open_bzip2_file_to_tmp_file(bzip2_filename: str) -> str:
	"""Open up a bzip2 file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, bz2.BZ2File(bzip2_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding bzip2 file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def open_gzip_file_to_tmp_file(gzip_filename: str) -> str:
	"""Open up a gzip file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, gzip.GzipFile(gzip_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding gzip file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def packet_layers(pkt) -> List:
	"""Returns a list of packet layers."""

	layers = []
	counter = 0
	while True:
		layer = pkt.getlayer(counter)
		if layer is not None:
			#print(layer.name)
			layers.append(layer.name)
		else:
			break
		counter += 1

	return layers
	#Sample return	['Ethernet', 'IP', 'TCP']


def process_packet_source(if_name: Optional[str], pcap_source: Optional[str], user_args: Dict):
	"""Process the packets in a single source file, interface, or stdin."""

	source_file = None
	close_temp = False
	delete_temp = False

	#We have an interface to sniff on
	if if_name:
		debug_out('Reading packets from interface ' + if_name)
		try:
			if user_args['count']:
				sniff(store=0, iface=if_name, filter=user_args['bpf'], count=user_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
			else:
				sniff(store=0, iface=if_name, filter=user_args['bpf'], prn=lambda x: processpacket(x))					# pylint: disable=unnecessary-lambda
		except ((Scapy_Exception, PermissionError)):
			sys.stderr.write("Unable to open interface " + str(if_name) + ' .  Permission error?  Perhaps runs as root or under sudo?  Exiting.\n')
			raise
	#Read from stdin
	elif pcap_source in ('-', None):
		debug_out('Reading packets from stdin.')
		tmp_packets = tempfile.NamedTemporaryFile(delete=True)					# pylint: disable=consider-using-with
		tmp_packets.write(sys.stdin.buffer.read())
		tmp_packets.flush()
		source_file = tmp_packets.name
		close_temp = True
	#Set up source packet file; next 2 sections check for and handle compressed file extensions first, then final "else" treats the source as a pcap file
	else:
		pcap_source = cast(str, pcap_source)
		if pcap_source.endswith('.bz2'):
			debug_out('Reading bzip2 compressed packets from file ' + pcap_source)
			source_file = open_bzip2_file_to_tmp_file(pcap_source)
			delete_temp = True
		elif pcap_source.endswith('.gz'):
			debug_out('Reading gzip compressed packets from file ' + pcap_source)
			source_file = open_gzip_file_to_tmp_file(pcap_source)
			delete_temp = True
		else:
			debug_out('Reading packets from file ' + pcap_source)
			source_file = pcap_source

	#Try to process file first
	if source_file:
		if os.path.exists(source_file) and os.access(source_file, os.R_OK):
			try:
				if user_args['count']:
					sniff(store=0, offline=source_file, filter=user_args['bpf'], count=user_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
				else:
					sniff(store=0, offline=source_file, filter=user_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
			except (FileNotFoundError, IOError):
				sys.stderr.write("Unable to open file " + str(pcap_source) + ', exiting.\n')
				raise
		else:
			sys.stderr.write("Unable to open file " + str(source_file) + ', skipping.\n')

	if close_temp:
		tmp_packets.close()

	if source_file and delete_temp and source_file != pcap_source and os.path.exists(source_file):
		os.remove(source_file)


def processpacket(p):
	"""Process a single packet p.  We look for clues to scanning for IP addresses; at the moment that's ARP requests for IPv4 and Neighbor Solicitation ("NS") for IPv6."""

	if "arp_stats" not in processpacket.__dict__:
		processpacket.arp_stats = {}								# type: ignore

	#source_ip = ''
	#dest_ip = ''
	#if p.haslayer(IP):
	#	source_ip = p[IP].src
	#	dest_ip = p[IP].dst
	#elif p.haslayer(IPv6):
	#	source_ip = p[IPv6].src
	#	dest_ip = p[IPv6].dst

	#IPv6 doesn't have a dedicated ICMPv6 layer, so we need to key off the IPv6 next_header value of 58 for ICMPv6
	if p.haslayer(IPv6) and p.getlayer(IPv6).nh == 58 and p.getlayer(ICMPv6ND_NS):		#58: ICMPv6, 135 is ICMPv6ND_NS
		#NS_Layer = p.getlayer(ICMPv6ND_NS)
		#ICMP6_layer = p.getlayer('IPv6').payload
		#ICMP6_layer.show()
		#source_mac = '00:00:00:00:00:00'
		#if p.getlayer(ICMPv6NDOptSrcLLAddr):
		#	source_mac = p[ICMPv6NDOptSrcLLAddr].lladdr
		source_mac = p[Ether].src
		dest_mac = p[Ether].dst
		source_ip = p[IPv6].src
		dest_ip = p[IPv6].dst

		if source_ip not in ignore_list and dest_ip not in ignore_list and source_mac not in ignore_list and dest_mac not in ignore_list and ((source_ip != dest_ip) or include_self):	# pylint: disable=too-many-boolean-expressions,possibly-used-before-assignment
			if source_ip not in processpacket.arp_stats:
				processpacket.arp_stats[source_ip] = set()
			processpacket.arp_stats[source_ip].add(dest_ip)

	elif p.haslayer(ARP) and isinstance(p[ARP], ARP):
		if p[ARP].op == 1:									#Request/query
			source_mac = str(p[ARP].hwsrc)
			dest_mac = str(p[ARP].hwdst)

			source_ip = str(p[ARP].psrc)
			dest_ip = str(p[ARP].pdst)
			if source_ip not in ignore_list and dest_ip not in ignore_list and source_mac not in ignore_list and dest_mac not in ignore_list and ((source_ip != dest_ip) or include_self):	# pylint: disable=too-many-boolean-expressions
				if source_ip not in processpacket.arp_stats:
					processpacket.arp_stats[source_ip] = set()
				processpacket.arp_stats[source_ip].add(dest_ip)
		#elif p[ARP].op == 2:									#Reply
		#	pass

	#elif p.haslayer(IPv6) and p.getlayer(IPv6).nh == 58 and p.getlayer(ICMPv6TimeExceeded):		#58: ICMPv6
	#	pass
	#elif p.haslayer(IPv6) and p.getlayer(IPv6).nh == 0:	#0: Hop-by-hop options header
	#	pass
	#elif p.haslayer(Ether) and p[Ether].type == 0x886C:
	#	pass
	#elif p.haslayer(Ether) and p[Ether].type == 0x88CC:
	#	pass
	#elif p.haslayer(ICMP) and isinstance(p[ICMP], ICMP):
	#	pass
	#elif p.haslayer(IP) and p[IP].proto == 2:							#IGMP
	#	pass
	#elif p.haslayer(ICMPv6DestUnreach):
	#	pass
	#else:
	#	p.show()
	#	#If you just want to see one packet, add sys.exit to quit the program.
	#	#sys.exit(2)



def report_scanners(arp_statistics: Dict, min_dests: int):
	"""Show IP addresses that are sending arp requests to at least min_dests hosts."""

	#print(str(arp_statistics))
	for ind in arp_statistics:
		if len(arp_statistics[ind]) >= min_dests:
			if cl_args['verbose']:
				print(ind + '    ' + str(arp_statistics[ind]))				#Print all IPs scanned
			else:
				print(ind + '    ' + str(len(arp_statistics[ind])))			#Just print a count of IPs scanned


default_min_dests: int = 10
default_bpf: str = 'arp or icmp6[0] = 135'
include_self = False											#Should we include lookups from an IP to itself? This is likely checking to see if its IP is already in use
													#False: do _not_ remember a host looking up its own IP
													#True: _do_ remember a host looking up its own IP

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='scan_detect version ' + str(__version__))
	parser.add_argument('-i', '--interface', help='Interface from which to read packets', required=False, default=None)
	parser.add_argument('-r', '--read', help='Pcap file(s) from which to read packets (can be bzip2/gzip compressed)', required=False, default=[], nargs='*')
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed (default: ' + default_bpf + ')', required=False, default=default_bpf)
	parser.add_argument('-c', '--count', help='Number of packets to sniff (if not specified, sniff forever/until end of pcap file)', type=int, required=False, default=None)
	parser.add_argument('-m', '--min_dests', help='Minimum destinations before we show a source (default: ' + str(default_min_dests) + ')', type=int, required=False, default=default_min_dests)
	parser.add_argument('-v', '--verbose', help='Verbose output (show all addresses scanned)', required=False, default=False, action='store_true')
	parser.add_argument('--ignore_file', help='Name of the file containing mac addresses and/or IPs that should not be considered as source or dest (one per line, no wildcards)', type=str, required=False, default='')
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	debug_out("BPF we'll use is: " + cl_args['bpf'])

	ignore_list: List = []
	if cl_args['ignore_file']:
		ignore_list = read_list_from_file(cl_args['ignore_file'], True, True)

	read_from_stdin = False		#If stdin requested, it needs to be processed last, so we remember it here.  We also handle the case where the user enters '-' more than once by simply remembering it.
	if cl_args['interface'] is None and cl_args['read'] == []:
		debug_out('No source specified, reading from stdin.')
		read_from_stdin = True

	try:
		if cl_args['read']:
			#Process normal files first.
			for one_source in cl_args['read']:
				if one_source == '-':
					read_from_stdin = True
				else:
					process_packet_source(None, one_source, cl_args)

		#Now that normal files are out of the way process stdin and/or reading from an interface, either of which could be infinite.
		if read_from_stdin:
			process_packet_source(None, '-', cl_args)

		if cl_args['interface']:
			process_packet_source(cl_args['interface'], None, cl_args)
	except KeyboardInterrupt:
		#script immediately ends on ctrl-c.  Need to figure out signal handling to provide an intermediate report
		##Print intermediate report
		#report_scanners(processpacket.arp_stats, cl_args['min_dests'])				# type: ignore
		pass

	report_scanners(processpacket.arp_stats, cl_args['min_dests'])					# type: ignore
