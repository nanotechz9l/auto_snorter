#!/usr/bin/env ruby
require 'packetfu'; require 'rainbow'
# API dox http://planb-security.net/packetfu/doc/

# User supplies .pcap as an argument
pcap  = ARGV[0] || exit
count = 0
pcapd = PacketFu::Read.f2a(:file => pcap)   # alias for file_to_array
#processed_pcap = PacketFu::PcapFile.read.to_s(pcap) # does not work

# Parse / process the supplied .pcap
pcapd.each do |pkt|
v = PacketFu::Packet.parse(pkt)

# Begin packet count
count += 1
end

# Print packet count to user
title = "Packet attributes in '#{pcap}'".foreground(:white).bright
puts "-" * title.size
puts title
puts "-" * title.size

puts "#{count}".foreground(:magenta).bright + " packets".rjust(12).foreground(:magenta).bright

# Read file packets
r = PacketFu::PcapFile.read(pcap)

# Print packet size to user
puts "#{r}".size.to_s.foreground(:magenta).bright + " bytes\n".rjust(9).foreground(:magenta).bright
