# robdns: a DNS server

This DNS server bypasses the kernel, interacting with the network
using raw packets. It has built-in ARP, IP, UDP, and DNS protocol
stack. It is designed to handle the .com zone, servicing random
request at a rate of 10 million per second.

Currently it is in "prototype" stage. There is much that almost works,
but will still take some effort to finish.

# Building

On Debian/Ubuntu, it goes something like this:

	$ git clone https://github.com/robertdavidgraham/robdns
	$ cd robdns
	$ make

This puts the program in the `robdns/bin` subdirectory. You'll have to
manually copy it to something like `/usr/local/bin` if you want to
install it elsewhere on the system.

While Linux is the primary target platform, the code runs well on many other
systems. Here's some additional build info:
* Windows w/ Visual Studio: use the VS10 project
* Windows w/ MingGW: just type `make`
* Windows w/ cygwin: won't work
* Mac OS X /w XCode: use the XCode4 project
* Mac OS X /w cmdline: just type `make`
* FreeBSD: type `gmake`
* other: I don't know, don't care


# Usage

The easiest way to run this server is simply to run it on the command-line
with one or more DNS zone-files:

	# robdns example.zone

The zone file is assumed to be in standard BIND9 format starting with an
SOA record, and containing only records/glue within the zone.

By default, this will use the IP address of the primary network adapter.
This causes some difficulties, because incoming packets will be sent both
to the normal network stack and to this program. For best results, use
a different network address not used by another machine on the local subnet.

	# robdns example.con 192.168.1.222

To verify that it's working, use the `dig` tool:

	$ dig chaos txt version.bind @192.168.1.122

This should return a record with the value of `robdns/1`. Then, try normal
DNS requests, such as:

	$ dig ns1.example.com @192.168.1.122

# Features

This server has no particular features at this time, other than bypassing
the kernel.

# Authors

This tool created by Robert Graham:
email: robert_david_graham@yahoo.com
twitter: @ErrataRob






