# robdns: infrastructure DNS server

This is a fast, full-featured, authoritative DNS server. It can handle over one million
queries-per-second per CPU core. It is designed to be exposed to the Internet,
where even servers that have light loads of only 100,000 queries-per-second
may nonetheless be attacked with millions of queries-per-second.

Currently, it is in "prototype" stage. Most of the major functionality is
supported, but it still needs more unit tests written.


# Building

Just type `make` to build the software. This works on Windows (MinGW) and
Mac, too, although you may optionally use the VS10 and XCode projects instead.


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






