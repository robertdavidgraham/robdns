# robdns: a fast DNS server

This is the fastest authoritative DNS server, bypassing the kernel with it's 
own TCP/IP stack. It handles about 1-million queries/second for each CPU
core in a system.

Currently it is in "prototype" stage. There is much that almost works,
but will still take some effort to finish.

# Building

On Debian/Ubuntu, it goes something like this:

	$ git clone https://github.com/robertdavidgraham/robdns
	$ cd robdns
	$ make
	$ make regress

This puts the program in the `robdns/bin` subdirectory. You'll have to
manually copy it to something like `/usr/local/bin` if you want to
install it elsewhere on the system.

While Linux is the primary target platform, the code runs well on many other
systems. Here's some additional build info:
* Windows w/ Visual Studio: use the VS10 project
* Windows w/ MingGW: just type `make`
* Mac OS X: use the XCode project, or `make`


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

	# robdns example.zone 192.168.1.222

To verify that it's working, use the `dig` tool from another machine:

	$ dig chaos txt version.bind @192.168.1.122

This should return a record with the value of `robdns/1`. Then, try normal
DNS requests, such as:

	$ dig ns1.example.com @192.168.1.122

There is a sample `example.zone` file to test with in the top directory. Or,
consider getting a copy of the `com.zone` file (8-gigabytes) to test with.

# Features

This server has no particular features at this time, other than bypassing
the kernel.

# Authors

This tool created by Robert Graham:
email: robert_david_graham@yahoo.com
twitter: @ErrataRob






