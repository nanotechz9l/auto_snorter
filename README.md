
Auto Snorter
==============

This script automatically creates very simplified/dumb snort rules based on user input.

Written by Rick Flores @nanotechz9l

![Screenhot](http://img22.imageshack.us/img22/3401/pc36.png)

## Pre Reqs

You *MUST install the rainbow gem for the pretty colorized output seen above:

	gem install rainbow
	
	require 'rainbow'

## Usage
	./auto_snorter.rb
	

## Features
* Shell / Commandline (CLI) application allowing:
        * Follow the prompts, and you will end up with a fully working snort rule!
	* The snort rule syntax is all hardcoded for you, no need to worry... just follow the prompts ;)
        * Snort rule header action (alert, log, pass, reject... etc)
	* Protocol to analyze (tcp, udp, icmp, ip)
	* Source ip to monitor
        * Source port to monitor
        * Traffic direction operator to monitor
        * Destination ip
        * Destination port
        * Snort rule options, and message (msg: "Keylogger detected";
        * Snort content keywords
        * Classtype
        * Reference URL
        * SID
        * Revision

## Requirements
* Tested on ruby version/s:
	* ruby 2.0.0p0 (2013-02-24 revision 39474)
	
	* ruby 1.9.3

## History
* 09/9/2013 - Pseudocode, and got to work.
* 09/08/2013 - I had a dream that one day writing snort rules didnt have to be a pain!

## To Do
* Possible GUI interface in the future (drag/drop)
* This code is def BETA! It is only programmed to automatically generate stupid simple snort rules.
* Major refactoring is needed to add support for multiple rule headers/options/PCRE's, & update the logic to be *MORE intelligent

## Credits
* Rick Flores (@nanotechz9l) -- 0xnanoquetz9l[--at--]gmail.com

## License
This code is free software; you can redistribute it and/or modify it under the
terms of the new BSD License.
