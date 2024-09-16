#!/usr/bin/env python
"""Modify the packets in a pcap file, returning a new one with the modified packets."""

#Processes around 386 pps

__version__ = '0.9.2'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2018-2024, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Development'				#Prototype, Development or Production



import sys
import time											# pylint: disable=unused-import
from scapy.all import sniff, PcapWriter, IP, IPv6, ARP, UDP, TCP, GRE, VXLAN, Ether, Dot1Q	# pylint: disable=no-name-in-module
from scapy.contrib.erspan import ERSPAN
#from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

four_b = (2 ** 32) - 1		#Four billion; used in sequence numbers that wrap at 2^32 -1

tuple_stats = {}		#Dictionary: keys are port_tuple strings, values are lists: [packets_written, start_seq, payload_bytes_written] .  Start_seq used for tcp, bytes_written for udp.
base_timestamp = None		#Placed as global as we don't control the packet handling loop
bpfilter = ''


def tuple_string(c_proto, pkt, src_ip, dst_ip):
	"""Create a string desribing the connection as a key for the tuple_stats dictionary."""

	if c_proto in ('TCP6', 'TCP4'):
		sport = str(pkt[TCP].sport)
		dport = str(pkt[TCP].dport)
	elif c_proto in ('UDP6', 'UDP4'):
		sport = str(pkt[UDP].sport)
		dport = str(pkt[UDP].dport)
	else:
		sport = ''
		dport = ''

	return str(c_proto) + '_' + str(src_ip) + '_' + str(sport) + '_' + str(dst_ip) + '_' + str(dport)


def should_write_tcp(p, port_tuple):
	"""Decides whether the packet - aready known to be IPv4 or IPv6 TCP - should be written."""

	global tuple_stats
	#We use, but do not modify, the global dictionary "args", so we don't declare it global.

	write_tcp = True

	F = p['TCP'].flags
	Seq = int(p['TCP'].seq)

	if port_tuple not in tuple_stats:
		tuple_stats[port_tuple] = [0, None, 0]

	if (F & (SYN + FIN + RST)) == SYN:						#Syn set, fin/rst clear
		#Remember the Sequence number for this SYN or SYN/ACK packet
		tuple_stats[port_tuple][1] = Seq + 1					#Since ACK packets start using Seq+1, we store this
	elif F & (SYN + FIN + RST + ACK) == ACK:					#Ack set, Syn/Fin/Rst all false
		if tuple_stats[port_tuple][1] is None:					#We never got an initial Seq from a Syn or syn/ack - we may be coming in the middle of a tcp session.  Just grab the seq number from this packet to get the next (user requested) kilobytes.
			tuple_stats[port_tuple][1] = Seq
		if args['ackcount'] is not None and tuple_stats[port_tuple][0] > args['ackcount']:
			write_tcp = False
		#or args['ackbytes'] is not None and (Seq > tuple_stats[port_tuple][1]) and (Seq - tuple_stats[port_tuple][1] < args['ackbytes']):
		#	#FIXME - handle case where Seq < tuple_stats[port_tuple][1] + 1 by adding 4B
		#	pass
		#else:
		#	write_tcp = False

	return write_tcp


def should_write_udp(p, port_tuple):								# pylint: disable=unused-argument
	"""Decides whether the packet - aready known to be IPv4 or IPv6 UDP - should be written."""

	global tuple_stats
	#We use, but do not modify, the global dictionary "args", so we don't declare it global.

	write_udp = True

	if port_tuple not in tuple_stats:
		tuple_stats[port_tuple] = [0, None, 0]

	if args['udpcount'] is not None and tuple_stats[port_tuple][0] > args['udpcount']:
		write_udp = False

	return write_udp


def should_write(p):
	"""Returns true if the supplied packet should be written (matches requirements), false otherwise."""

	global tuple_stats
	#We use, but do not modify, the global dictionary "args", so we don't declare it global.

	write_it = True
	port_tuple = 'Pkt____'

	if p.haslayer(IPv6) and isinstance(p[IPv6], IPv6):					#IPv6
		sIP = str(p['IPv6'].src)
		dIP = str(p['IPv6'].dst)
		if p['IPv6'].nh == 6 and p.haslayer(TCP): 					#TCPv6
			if args['ackcount'] is not None or args['ackbytes'] is not None:
				port_tuple = tuple_string('TCP6', p, sIP, dIP)
				write_it = should_write_tcp(p, port_tuple)
		elif (p['IPv6'].nh == 17) and p.haslayer(UDP): 					#UDPv6
			if args['udpcount'] is not None or args['udpbytes'] is not None:
				port_tuple = tuple_string('UDP6', p, sIP, dIP)
				write_it = should_write_udp(p, port_tuple)
		else:
			port_tuple = tuple_string('IPv6', p, sIP, dIP)				#Mangled TCP/UDP or non-TCP/UDP packet, write unconditionally
	elif p.haslayer(IP) and isinstance(p[IP], IP):						#IPv4
		sIP = str(p['IP'].src)
		dIP = str(p['IP'].dst)
		if p['IP'].proto == 6 and p.haslayer(TCP) and isinstance(p[TCP], TCP):		#TCPv4
			if args['ackcount'] is not None or args['ackbytes'] is not None:
				port_tuple = tuple_string('TCP4', p, sIP, dIP)
				write_it = should_write_tcp(p, port_tuple)
		elif p['IP'].proto == 17 and p.haslayer(UDP) and isinstance(p[UDP], UDP):	#UDPv4
			if args['udpcount'] is not None or args['udpbytes'] is not None:
				port_tuple = tuple_string('UDP4', p, sIP, dIP)
				write_it = should_write_udp(p, port_tuple)
		else:
			port_tuple = tuple_string('IPv4', p, sIP, dIP)				#Mangled TCP/UDP or non-TCP/UDP packet, write unconditionally
	elif p.haslayer(ARP) and isinstance(p[ARP], ARP):					#ARP
		sIP = str(p['ARP'].psrc)
		dIP = str(p['ARP'].pdst)
		port_tuple = tuple_string('ARP', p, sIP, dIP)
	else:
		port_tuple = tuple_string('Other', p, '', '')
		#p.show()
		#quit()

	if port_tuple and port_tuple not in tuple_stats:
		tuple_stats[port_tuple] = [0, None, 0]

	if args['maxseconds'] is not None:
		if (p.time - base_timestamp) > args['maxseconds']:
			write_it = False

	if write_it:
		tuple_stats[port_tuple][0] += 1

	if args['verbose'] and port_tuple:
		print(port_tuple + ":   " + str(tuple_stats[port_tuple]) + " " + str(write_it))

	return write_it


def decapsulate_a_packet(orig_pkt):
	"""If this packet is a VXLAN, 802.1Q, or GRE packet, strip out the encapsulation and return the original packet."""

	#For development
	#orig_pkt.show()
	#print('========')

	if orig_pkt.haslayer(Ether) and orig_pkt.haslayer(Dot1Q):
		#Scapy does not appear to allow deleting a single layer, in this case Dot1Q (802.1Q).
		#Deleting any layer deletes the layer and everything that follows.

		original_post_dot1q_type = orig_pkt[Dot1Q].type			#Instead we remember the type of the embedded packet

		original_ethernet = orig_pkt[Ether].copy()			#, grab the Ethernet header
		del original_ethernet[Dot1Q]

		original_embedded_packet = orig_pkt[Dot1Q].payload		#, everything that follows 802.1Q

		new_pkt = original_ethernet/original_embedded_packet		#, and build the new packet from the ethernet header and the embedded packet

		new_pkt[Ether].type = original_post_dot1q_type			#Finally we force the type field in the ethernet header to match the embedded packet (it used to be Dot1Q)
	elif orig_pkt.haslayer(Dot1Q):
		print("Ethernet-less Dot1, exiting.")
		sys.exit(1)
	elif orig_pkt.haslayer(IP) and (orig_pkt[IP].proto in (4, 41)):		#Outer IP header has "ipencap" or "ipv6" as next protocol
		#Delete first IP header like above

		original_ethernet = orig_pkt[Ether].copy()			#, grab the Ethernet header
		del original_ethernet[IP]

		original_embedded_packet = orig_pkt[IP].payload			#, everything that follows the first IP header

		new_pkt = original_ethernet/original_embedded_packet		#, and build the new packet from the ethernet header and the embedded packet

		if orig_pkt[IP].proto == 41:					#Only need to replace the Ethertype if we earlier had Ether-IP-IPv6 (in this case, force it to IPv6)
			new_pkt[Ether].type = 0x86DD
	elif orig_pkt.haslayer(VXLAN):
		#The extracted packet has its own Ethernet header so we don't need to manually create one
		new_pkt = orig_pkt[VXLAN].payload
	elif orig_pkt.haslayer(ERSPAN):
		new_pkt = orig_pkt[ERSPAN].payload
	elif orig_pkt.haslayer(GRE):
		#The encapsulated packet does not have its own ethernet header so we build one field by field
		new_pkt = Ether()/orig_pkt[GRE].payload
		new_pkt[Ether].dst = orig_pkt[Ether].dst
		new_pkt[Ether].src = orig_pkt[Ether].src
		if new_pkt.haslayer(IPv6):
			new_pkt[Ether].type = 0x86DD				#IPv6
		elif new_pkt.haslayer(IP):
			new_pkt[Ether].type = 0x800				#IPv4
		else:
			new_pkt[Ether].type = orig_pkt[Ether].type
	else:
		new_pkt = orig_pkt

	#For development
	#new_pkt.show()
	#time.sleep(5)

	return new_pkt


def stopfilter(one_pkt) -> bool:
	"""Decide whether we should continue sniffing or not.  A return
	of True means STOP sniffing; a return of false means CONTINUE
	sniffing.  At the moment we only return True if we exceed the
	number of seconds defined in CLP ---maxseconds ."""

	global base_timestamp

	shouldstop = False
	if args['maxseconds'] is not None:
		if not base_timestamp:
			base_timestamp = one_pkt.time

		if (one_pkt.time - base_timestamp) > args['maxseconds']:
			shouldstop = True

	return shouldstop


def process_a_packet(pkt):
	"""Handle a single packet read from the input pcap file."""

	global out_handle
	global base_timestamp
	#We use, but do not modify, "args" so we don't declare it as global.

	#For development
	#if (pkt.haslayer(IPv6) or pkt.haslayer(IP)) and pkt.haslayer(TCP):
	#pkt.show()
	#pkt[IP].payload.show()
	#time.sleep(5)


	if args['timescale'] or args['delta'] or (args['maxseconds'] is not None):
		if not base_timestamp:
			base_timestamp = pkt.time
		delta_time = pkt.time - base_timestamp

		if args['timescale'] or args['delta']:
			pkt.time = base_timestamp + (args['timescale'] * delta_time) + args['delta']

	if should_write(pkt):
		if args['decap'] and (pkt.haslayer(VXLAN) or pkt.haslayer(ERSPAN) or pkt.haslayer(GRE) or pkt.haslayer(Dot1Q) or (pkt.haslayer(IP) and (pkt[IP].proto in (4, 41)))):
			pmod = decapsulate_a_packet(pkt)
		else:
			pmod = pkt
		out_handle.write(pmod)



#======== Main
if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='Modify a pcap file, version' + str(__version__))
	parser.add_argument('-r', '--read', help='File from which to read packets', required=True)
	parser.add_argument('-w', '--write', help='File to which to write packets', required=True)
	parser.add_argument('-t', '--timescale', help='Multiplier for time scale', required=False, type=float, default=1.0)
	parser.add_argument('-d', '--delta', help='Number of seconds to add to every timestamp (postive or negative fine)', required=False, type=float, default=0.0)
	parser.add_argument('-v', '--verbose', help='Print info about each packet', dest='verbose', action='store_true', required=False, default=False)
	parser.add_argument('--ackcount', help='Maximum number of ACK packets to write on one side of a TCP connection', required=False, type=int, default=None)
	parser.add_argument('--ackbytes', help='ackbytes - not yet implemented', required=False, type=int, default=None)
	parser.add_argument('--udpcount', help='Maximum number of UDP packets to write on one side of a UDP conversation', required=False, type=int, default=None)
	parser.add_argument('--udpbytes', help='udpbytes - not yet implemented', required=False, type=int, default=None)
	parser.add_argument('--decap', help='Decapsulate packets (strips vxlan, 802.1Q, ERSPAN, GRE, IPIP, and IPIPv6)', action='store_true', required=False, default=False)
	parser.add_argument('--maxseconds', help='Maximum number of seconds of packets to write', required=False, type=float, default=None)
	args = vars(parser.parse_args())
	#FIXME - add --summary argument and show in and out stats


	if args['write']:
		try:
			out_handle = PcapWriter(filename=args['write'])
		except:
			print("Unable to open " + str(args['write']) + " for write, exiting.")
			raise
			#quit(1)

	try:
		sniff(store=0, offline=args['read'], filter=bpfilter, stop_filter=stopfilter, prn=lambda x: process_a_packet(x))	# pylint: disable=unnecessary-lambda
	except IOError:
		print("Unable to open " + str(args['read']) + ' , exiting.')
		raise
		#quit(1)
