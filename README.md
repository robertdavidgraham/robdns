# robdns: infrastructure DNS server

This is a fast super-slave DNS server, designed to be constantly attacked
on the public Internet. The intent is to shield master servers that are
hidden behind firewalls. The key feature is a built-in custom TCP/IP stack
capable of handling millions of DNS queries-per-second per CPU core.

Currently, this tool is in a prototype stage. It parses records and
responds to queries on port 53, but it's missing key features such
as dynamic updates.


# Building

The only dependency is `libpcap-dev` (or `WinPcap`).

Just type `make` to build the software on Linux, Mac OS X, and Windows 
(MinGW).

The included XCode4 and VS10 projects should also work on Mac and 
Windows respectively.


# Running

The easiest way to test the server is to run on the comman-line with one
or more DNS zone-files, like so:

	# robdns example.zone

This will start listening on the `any` IP address (v4 and v6) on port 53.
Zone-files are in the standard format, with a filename ending in `.zone`,
and starting with an SOA record.

To test that it's running, you can use the normal `dig` command.

	$ dig chaos txt version.bind @localhost +short
    
You should get back the version string of `robdns/1`.


However, the above example is the **slow** way of running the software.
The intended use is to bypass the kernel's network stack using special
drivers like PF_RING. To run in this faster mode, install the drivers
and run with a command like the following:

    # robdns example.zone dna0 192.168.1.222

In this example, the server will use it's own user-mode TCP/IP stack
instead. Currently, this benchmarks to about 1-million packets-per-second
for each CPU core.


# Feature status

The following RR types have been implemented:

	SOA, NS,
	A, AAAA, PTR, CNAME,
	SSHFP, LOC, TXT, SRV, SPF, HINFO, MX,
	DNSKEY, NSEC, NSEC3, NSEC3PARAM, RRSIG, DS, TLSA,
	EDNS0,
	

The following interfaces are supported:
	sockets, libpcap, PF_RING



# Authors

This tool created by Robert Graham:
email: robert_david_graham@yahoo.com
twitter: @ErrataRob






