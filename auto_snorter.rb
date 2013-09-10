#!/usr/bin/env ruby 
require 'rainbow'

# This script automatically creates very simplified snort rules based on user input.
# Written by Rick Flores @nanotechz9l

=begin
 def banner()
 print """ 
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          _____ ____   
          ----,\    )
           --==\\  /           Auto Snorter v0.0.1 Locked, stocked, and fully auto swine time... <////~
            --==\\/
          .-~~~~-.Y|\\_        by Rick Flores @nanotechz9l
       @_/        /  66\_      0xnanotechz9l@gmail.com
         |    \   \   _(")
          \   /-| ||'--'       Automation station!
            \_\  \_\\
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
print """ 
=end

prompt			= 'auto_snorter:~#'
rule_action		= ARGV[0]
protocol		= ARGV[1]
src_ip			= ARGV[2]
src_port		= ARGV[3]
traffic_direction	= ARGV[4]
dst_ip			= ARGV[5]
dst_port		= ARGV[6]
rule_msg		= ARGV[7]
rule_options		= ARGV[8]
content_keyword		= ARGV[9]
classtype		= ARGV[10]
ref_url			= ARGV[11]
sid			= ARGV[12]
rev			= ARGV[13]



puts "\n\nI will create a snort rule automatically for you".foreground(:blue).bright
puts "In order to generate the rule, I need to ask you a few questions.".foreground(:blue).bright
puts "\n\nWhich rule header option do you wish to use?".foreground(:red).bright
puts "Options available:\n".foreground(:red).bright

puts "alert - generate an alert using the selected alert method, and then log the packet".foreground(:cyan).bright
puts "log - log the packet".foreground(:cyan).bright
puts "pass - ignore the packet".foreground(:cyan).bright
puts "activate - alert and then turn on another dynamic rule".foreground(:cyan).bright
puts "dynamic - remain idle until activated by an activate rule , then act as a log rule".foreground(:cyan).bright
puts "drop - block and log the packet".foreground(:cyan).bright
puts "reject - block the packet, log it, and then send a TCP reset if the protocol is TCP or an ICMP port unreachable message if the protocol is UDP.".foreground(:cyan).bright
puts "sdrop - block the packet but do not log it.".foreground(:cyan).bright
print prompt
rule_action = STDIN.gets.chomp()

puts
puts "What protocol do you wish to analyze?".foreground(:red).bright
puts "Options available:\n".foreground(:cyan).bright

puts "TCP, UDP, IP, ICMP".foreground(:cyan).bright
puts "In the future there may be more, such as ARP, IGRP, GRE, OSPF, RIP, IPX, etc.".foreground(:cyan).bright
print prompt
protocol = STDIN.gets.chomp()

puts
puts "Whats the source ip address you wish to monitor?".foreground(:red).bright
print prompt
src_ip = STDIN.gets.chomp()

puts
puts "Whats the source port you wish to monitor?".foreground(:red).bright
print prompt
src_port = STDIN.gets.chomp()

puts
puts "Whats the destination ip address you wish to monitor?".foreground(:red).bright
print prompt
dst_ip = STDIN.gets.chomp()

puts
puts "Whats the destination port you wish to monitor?".foreground(:red).bright
print prompt
dst_port = STDIN.gets.chomp()

puts
puts "Whats the traffic direction you wish to monitor?".foreground(:red).bright
puts "Options available: ->, <>".foreground(:cyan).bright
print prompt
traffic_direction = STDIN.gets.chomp()

puts
puts "What rule message do you wish to use?".foreground(:red).bright
puts "Options available: Keylogger detected, APT, TROJAN, C2 Initial Beacon..... etc...".foreground(:cyan).bright
print prompt
rule_msg = STDIN.gets.chomp()

puts
puts "What rule options do you wish to use?".foreground(:red).bright
puts "Content options available: content, nocase, rawbytes, ..... etc... coming soon".foreground(:cyan).bright
print prompt
rule_options = STDIN.gets.chomp()

puts
puts "What content keyword do you wish to use?".foreground(:red).bright
puts "Options available are whatever you like them to be: w0rm1, 77 30 72 6d 31..... etc... coming soon".foreground(:cyan).bright
print prompt
content_keyword = STDIN.gets.chomp()


puts
puts "What classtype do you wish to use?".foreground(:red).bright
puts "Options available:" 
puts "attempted-admin, attempted-user, inappropriate-content, policy-violation, shellcode-detect".foreground(:cyan).bright
puts "successful-admin, successful-user, trojan-activity, unsuccessful-user, web-application-attack".foreground(:cyan).bright 
puts "attempted-dos, attempted-recon, bad-unknown, default-login-attempt, denial-of-service, misc-attack, non-standard-protocol".foreground(:cyan).bright
puts "rpc-portmap-decode, successful-dos, successful-recon-largescale, successful-recon-limited, suspicious-filename-detect, suspicious-login".foreground(:cyan).bright
puts "system-call-detect, unusual-client-port-connection, web-application-activity, icmp-event, misc-activity, network-scan".foreground(:cyan).bright
puts "not-suspicious, protocol-command-decode, string-detect, unknown, tcp-connection".foreground(:cyan).bright
print prompt
classtype = STDIN.gets.chomp()

puts
puts "What reference URL do you wish to use?".foreground(:red).bright
puts "PLEASE NOTE THAT THE http://www. IS NOT NEEDED AS ITS ALREADY HARDCODED FOR YOU!".foreground(:cyan).bright
puts "Options available are: fireeye.com/blog/technical/botnet-activities/w0rm.html, etc....".foreground(:cyan).bright
print prompt
ref_url = STDIN.gets.chomp()

puts
puts "What SID do you wish to use?".foreground(:red).bright
puts "Options available:".foreground(:cyan).bright
puts "< (less than) 100 Reserved for future use".foreground(:cyan).bright
puts "100-999,999 Rules included with the Snort distribution".foreground(:cyan).bright
puts ">= (greater than or =) 1,000,000 Used for local rules".foreground(:cyan).bright

print prompt
sid = STDIN.gets.chomp()

puts
puts "What revision do you wish to use?".foreground(:red).bright
puts "Options available are any numerical value 1..10... etc".foreground(:cyan).bright
print prompt
rev = STDIN.gets.chomp()

puts
puts <<MESSAGE
Snort rule created successfully: 
#{rule_action} #{protocol} #{src_ip} #{src_port} #{traffic_direction} #{dst_ip} #{dst_port} (msg: "#{rule_msg}"; #{rule_options}; "#{content_keyword}"; reference:url,#{ref_url; }; classtype:#{classtype}; sid: #{sid}; rev:#{rev})
MESSAGE
puts