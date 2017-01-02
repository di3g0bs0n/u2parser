#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Diego Fernandez <di3g0bson@gmail.com>.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#



import os, sys, binascii, struct, netaddr, datetime

class u2(object):


	# Constants
	PACKET = 2
	EVENT = 7
	EVENT_IP6 = 72
	EVENT_V2 = 104
	EVENT_V2_IP6 = 105
	EXTRA_DATA = 110

	ICMP = 1
	ICMP6 = 58
	IP4 = 4
	IP6 = 41
	TCP = 6
	UDP = 17

	protocols = {
		ICMP: "ICMP",
		ICMP6: "ICMP v6",
		IP4: "IPv4",
		IP6: "IPv6",
		TCP: "TCP",
		UDP: "UDP",
	}

	FMTS = {
		'header': ("!2I",["record_type", "record_length"]),
		PACKET: ("!7I", ["sensor_id","event_id","event_seconds","packet_seconds","packet_microseconds","linktype","packet_length"], "packet_data"),
		EVENT: ("!11I2H4B",["sensor_id","event_id","event_seconds","event_microseconds","signature_id","generator_id","signature_revision","classification_id","priority_id","ip_source","ip_destination","srcport/icmptype","dstport/icmpcode","protocol","impact_flag","impact","blocked"]),
		EVENT_IP6: ("!9I16s16s2H4B",["sensor_id","event_id","event_seconds","event_microseconds","signature_id","generator_id","signature_revision","classification_id","priority_id","ip_source","ip_destination","srcport/icmptype","dstport/icmpcode","protocol","impact_flag","impact","blocked"]),
		EVENT_V2: ("!11I2H4BI2H", ["sensor_id","event_id","event_seconds","event_microseconds","signature_id","generator_id","signature_revision","classification_id","priority_id","ip_source","ip_destination","srcport/icmptype","dstport/icmpcode","protocol","impact_flag","impact","blocked","mpls_label","vlan_id","padding"]),
		EVENT_V2_IP6: ("!9I16s16s2H4BI2H",["sensor_id","event_id","event_seconds","event_microseconds","signature_id","generator_id","signature_revision","classification_id","priority_id","ip_source","ip_destination","srcport/icmptype","dstport/icmpcode","protocol","impact_flag","impact","blocked","mpls_label","vlan_id","padding"]),
		EXTRA_DATA: ("!6I",["sensor_id","event_id","event_seconds","type","data_type","data_length"],"data")
	}

	def __init__(self, filename, sid_file = '/etc/snort/sid-msg.map'):
		self.filename = filename
		self.content = self.readBinary()
		self.sid_file = sid_file
		self.messages = {}
		self.readSidMsg()

	def readBinary(self):
		"""
			Read  a binary file (unified2 log) and returns the content
		"""
		f = open(self.filename, 'rb')
		bytes = f.read()
		f.close()
		return bytes

	def readSidMsg(self):
		if os.path.isfile(self.sid_file):
			f = open(self.sid_file, 'r')
			for line in f.readlines():
				try:
					if line.strip().startswith("#"):
						continue
					line = line.replace("\n", "")
					fields = line.split("||")
					if len(fields) < 6:
						# Invalid Format
						continue

					gid = int(fields[0].strip())
					sid = int(fields[1].strip())
					rev = int(fields[2].strip())
					classification =  fields[3].strip()
					priority = int(fields[4].strip())
					msg =  fields[5].strip()

					self.messages[sid] = msg
				except:
					continue
			f.close()

	def hasItem(self, obj, n):
		"""
			Check if object (list or tuple) has an item.
		"""
		if type(obj) is dict: 
			try:
				a = obj[n]
				return True
			except KeyError:
				return False
		elif type(obj) is tuple:
			if type(n) is int:
				try:
					a = obj[n]
					return True
				except IndexError as e:
					return False
			else:
				return False


	def ts2date(self, ms):
		format = '%Y-%m-%d %H:%M:%S'
		return datetime.datetime.fromtimestamp(ms).strftime(format)


	def parse(self):
		"""
			Parse the file. Returns a list of IDS Events.
		"""
		records = []
		
		while True:
			size = struct.calcsize(self.FMTS['header'][0])
			record_type, record_length = struct.unpack(self.FMTS['header'][0], self.content[0:size])
			self.content = self.content = self.content[size:]
			
			try:
				size = struct.calcsize(self.FMTS[record_type][0])
				fields = struct.unpack(self.FMTS[record_type][0], self.content[0:size])
				packet = {}
				for item in zip(self.FMTS[record_type][1], list(fields)):
					packet[item[0]] = item[1]
				if self.hasItem(self.FMTS[record_type], 2) and struct.calcsize(self.FMTS[record_type][0]) != record_length:
					# Dynamically
					packet[self.FMTS[record_type][2]] = self.content[size:record_length]
				
				# Adjustments
				packet["record_type"] = record_type
				if self.hasItem(packet, 'event_seconds'):
						packet['date'] = self.ts2date(packet['event_seconds'])

				if record_type in [self.EVENT, self.EVENT_IP6, self.EVENT_V2, self.EVENT_V2_IP6]:
					try:
						packet['proto'] = self.protocols[packet['protocol']]
					except:
						packet['proto'] = packet['protocol']

						
					try:
						packet['msg'] = self.messages[packet['signature_id']]
					except:
						print "[!] Msg not found (%s)" % self.sid_file 
						packet['msg'] = '**Unknowkn Alert**'

					# Events
					if record_type in [self.EVENT_IP6, self.EVENT_V2_IP6]:
						ip_source = str(netaddr.IPAddress(int(binascii.hexlify(packet["ip_source"]), 16)))
						ip_destination = str(netaddr.IPAddress(int(binascii.hexlify(packet["ip_destination"]), 16)))
						packet["ip_source"] = ip_source
						packet["ip_destination"] = ip_destination
					elif record_type in [self.EVENT, self.EVENT_V2]:
						ip_source = str(netaddr.IPAddress(packet["ip_source"]))
						ip_destination = str(netaddr.IPAddress(packet["ip_destination"]))
						packet["ip_source"] = ip_source
						packet["ip_destination"] = ip_destination


					if packet['protocol'] in [self.ICMP, self.ICMP6]:
						icmp_type = packet["srcport/icmptype"]
						icmp_code = packet["dstport/icmpcode"]
						del packet["srcport/icmptype"]
						del packet["dstport/icmpcode"]
						packet["icmp_type"] = icmp_type
						packet["icmp_code"] = icmp_code
					else:
						srcport = packet["srcport/icmptype"]
						dstport = packet["dstport/icmpcode"]
						del packet["srcport/icmptype"]
						del packet["dstport/icmpcode"]
						packet["srcport"] = srcport
						packet["dstport"] = dstport



				
				# Add Record
				records.append(packet)
			except KeyError as e:
				# Unknown record Type
				if __name__ == "__main__":
					print ""
					print "[!] ERROR: Unknown record type (%s)" % record_type
					print ""

			self.content = self.content[record_length:]

			if self.content is None or len(self.content) == 0:
				break


		return records

