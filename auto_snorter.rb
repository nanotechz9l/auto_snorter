#!/usr/bin/env ruby 
require 'rainbow'

# This script automatically creates very simplified snort rules based on user input.

=begin
 def banner()
 print """ 
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
          _____ ____   
          ----,\    )
           --==\\  /           Auto Snorter v0.0.1 Locked, stocked, and fully auto swine time... <////~
            --==\\/
          .-~~~~-.Y|\\_        by Rick Flores @nanotechz9l
       @_/        /  66\_      0xnanoquetz9l[--at--]gmail.com
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

puts "[+]".foreground(:cyan).bright + " alert".foreground(:blue).bright    + " \t- generate an alert using the selected alert method, and then log the packet".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " log".foreground(:blue).bright      + " \t- log the packet".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " pass".foreground(:blue).bright     + " \t- ignore the packet".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " activate".foreground(:blue).bright + " \t- alert and then turn on another dynamic rule".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " dynamic".foreground(:blue).bright  + " \t- remain idle until activated by an activate rule , then act as a log rule".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " drop".foreground(:blue).bright     + " \t- block and log the packet".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " reject".foreground(:blue).bright   + " \t- block the packet, log it, and then send a TCP reset if the protocol is TCP or an ICMP port unreachable message if the protocol is UDP.".foreground(:cyan).bright
puts "[+]".foreground(:cyan).bright + " sdrop".foreground(:blue).bright    + " \t- block the packet but do not log it.".foreground(:cyan).bright
print prompt
rule_action = STDIN.gets.chomp()

puts
puts "What protocol do you wish to analyze?".foreground(:red).bright
puts "Options available:\n".foreground(:cyan).bright

puts "[+] TCP, UDP, IP, ICMP".foreground(:cyan).bright
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
puts "Whats the traffic direction you wish to monitor?".foreground(:red).bright
puts "Options available:".foreground(:cyan).bright 
puts "[+] ->, <>".foreground(:cyan).bright
print prompt
traffic_direction = STDIN.gets.chomp()

puts
puts "Whats the destination ip address you wish to monitor?".foreground(:red).bright
print prompt
dst_ip = STDIN.gets.chomp()

puts
puts "Whats the destination port you wish to monitor?".foreground(:red).bright
print prompt
dst_port = STDIN.gets.chomp()

puts
puts "What rule message do you wish to use?".foreground(:red).bright
puts "Options available: Message can be whatever you want it to be! Keylogger detected, APT, TROJAN, C2 Initial Beacon..... etc...".foreground(:cyan).bright
print prompt
rule_msg = STDIN.gets.chomp()

puts
puts "What rule options do you wish to use?".foreground(:red).bright
puts "Content options available: content, nocase, rawbytes, ..... etc... *FULL official snort options coming soon".foreground(:cyan).bright
print prompt
rule_options = STDIN.gets.chomp()

puts
puts "What content keyword do you wish to use?".foreground(:red).bright
puts "Options available are whatever you like them to be based on your malware sample! w0rm1, 77 30 72 6d 31..... etc...".foreground(:cyan).bright
print prompt
content_keyword = STDIN.gets.chomp()


puts
puts "What classtype do you wish to use?".foreground(:red).bright
puts "Options available:"
puts "  ______________________________________________________________________________________________________________  "
puts " |Classtype                      | Description                                                   | Priority     | "
puts " ---------------------------------------------------------------------------------------------------------------- "
puts "  attempted-admin".foreground(:blue).bright + "                | Attempted Administrator Privilege Gain                        | high         | "
puts "  attempted-user".foreground(:blue).bright + "                 | Attempted User Privilege Gain                                 | high         | "
puts "  inappropriate-content".foreground(:blue).bright + "          | Inappropriate Content was Detected                            | high         | "
puts "  policy-violation".foreground(:blue).bright + "               | Potential Corporate Privacy Violation                         | high         | "
puts "  shellcode-detect".foreground(:blue).bright + "               | Executable code was detected                                  | high         | "
puts "  successful-admin".foreground(:blue).bright + "               | Successful Administrator Privilege Gain                       | high         | "
puts "  successful-user".foreground(:blue).bright + "                | Successful User Privilege Gain                                | high         | "
puts "  trojan-activity".foreground(:blue).bright + "                | A Network Trojan was detected                                 | high         | "
puts "  unsuccessful-user".foreground(:blue).bright + "              | Unsuccessful User Privilege Gain                              | high         | "
puts "  web-application-attack".foreground(:blue).bright + "         | Web Application Attack                                        | high         | "
puts "  attempted-dos".foreground(:blue).bright + "                  | Attempted Denial of Service                                   | medium       | "
puts "  attempted-recon".foreground(:blue).bright + "                | Attempted Information Leak                                    | medium       | "
puts "  bad-unknown".foreground(:blue).bright + "                    | Potentially Bad Traffic                                       | medium       | "
puts "  default-login-attempt".foreground(:blue).bright + "          | Attempt to login by a default username and password           | medium       | "
puts "  denial-of-service".foreground(:blue).bright + "              | Detection of a Denial of Service Attack                       | medium       | "
puts "  misc-attack".foreground(:blue).bright + "                    | Misc Attack                                                   | medium       | "
puts "  non-standard-protocol".foreground(:blue).bright + "          | Detection of a non-standard protocol or event                 | medium       | "
puts "  rpc-portmap-decode".foreground(:blue).bright + "             | Decode of an RPC Query                                        | medium       | "
puts "  successful-dos".foreground(:blue).bright + "                 | Denial of Service                                             | medium       | "
puts "  successful-recon-largescale".foreground(:blue).bright + "    | Large Scale Information Leak                                  | medium       | "
puts "  successful-recon-limited".foreground(:blue).bright + "       | Information Leak                                              | medium       | "
puts "  suspicious-filename-detect".foreground(:blue).bright + "     | A suspicious filename was detected                            | medium       | "
puts "  suspicious-login".foreground(:blue).bright + "               | An attempted login using a suspicious user- name was detected | medium       | "
puts "  system-call-detect".foreground(:blue).bright + "             | A system call was detected                                    | medium       | "
puts "  unusual-client-port-connection".foreground(:blue).bright + " | A client was using an unusual port                            | medium       | "
puts "  web-application-activity".foreground(:blue).bright + "       | Access to a potentially vulnerable web application            | medium       | "
puts "  icmp-event".foreground(:blue).bright + "                     | Generic ICMP event                                            | low          | "
puts "  misc-activity".foreground(:blue).bright + "                  | Misc activity                                                 | low          | "
puts "  network-scan".foreground(:blue).bright + "                   | Detection of a Network Scan                                   | low          | "
puts "  not-suspicious".foreground(:blue).bright + "                 | Not Suspicious Traffic                                        | low          | "
puts "  protocol-command-decode".foreground(:blue).bright + "        | Generic Protocol Command Decode                               | low          | "
puts "  string-detect".foreground(:blue).bright + "                  | A suspicious string was detected                              | low          | "
puts "  unknown".foreground(:blue).bright + "                        | Unknown Traffic                                               | low          | "
puts "  tcp-connection".foreground(:blue).bright + "                 | A TCP connection was detected                                 | very low     | "
puts "  _______________________________________________________________________________________________________________ "


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
#{rule_action} #{protocol} #{src_ip} #{src_port} #{traffic_direction} #{dst_ip} #{dst_port} (msg: "#{rule_msg}"; #{rule_options}:"#{content_keyword}"; reference:url,#{ref_url; }; classtype:#{classtype}; sid: #{sid}; rev:#{rev})
MESSAGE
puts