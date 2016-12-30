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



import sys, binascii, struct, netaddr

class u2(object):

	# Constants
	FMTS = {
		'header': ("!2I",["record_type", "record_length"]),
		2: ("!7I", ["sensor_id","event_id","event_second","packet_seconds","packet_microseconds","linktype","packet_length"], "packet_data"),
		104: ("!11I2H4BI2h", ["sensor_id","event_id","event_second","event_microsecond","signature_id","generator_id","signature_revision","classification_id","priority_id","ip_source","ip_destination","srcport/icmptype","dstport/icmpcode","protocol","impact_flag","impact","blocked","mpls_label","vlan_id","padding"]),
		110: ("!6I",["sensor_id","event_id","event_second","type","data_type","data_length"],"data")
	}

	def __init__(self, filename, sidmsg = None):
		self.filename = filename
		self.content = self.readBinary()

	def readBinary(self):
		"""
			Read  a binary file (unified2 log) and returns the content
		"""
		f = open(self.filename, 'rb')
		bytes = f.read()
		f.close()
		return bytes

	def hasItem(self, obj, n):
		"""
			Check if object (list or tuple) has an item.
		"""
		try:
			a = obj[n]
			return True
		except:
			return False

	def parse(self):
		"""
			Parse the file. Returns a list of IDS Events.
		"""
		records = []
		
		while True:
			size = struct.calcsize(self.FMTS['header'][0])
			record_type, record_length = struct.unpack(self.FMTS['header'][0], self.content[0:size])
			self.content = self.content = self.content[size:]
			

			size = struct.calcsize(self.FMTS[record_type][0])
			fields = struct.unpack(self.FMTS[record_type][0], self.content[0:size])
			packet = {}
			for item in zip(self.FMTS[record_type][1], list(fields)):
				packet[item[0]] = item[1]
			if self.hasItem(self.FMTS[record_type], 2) and struct.calcsize(self.FMTS[record_type][0]) != record_length:
				# Dynamically
				packet[self.FMTS[record_type][2]] = self.content[size:record_length]
			
			# Add Record
			records.append(packet)

			self.content = self.content[record_length:]

			if self.content is None or len(self.content) == 0:
				break


		return records

