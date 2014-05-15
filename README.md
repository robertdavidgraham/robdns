# robdns: an infrastructure-class DNS server

This is a fast, fully-featured DNS server. It can handle over one million
queries-per-second per CPU core. It is designed to be exposed to the Internet,
where even servers that have light loads of only 100,000 queries-per-second
must nonetheless be attacked with millions of queries-per-second.

Currently, it is in "prototype" stage. Most of the major functionality is
supported, but it still needs more unit tests written.


# Building

Just type `make` to build the software. This works on Windows (MinGW) and
Mac, too, although you may optionally use the VS10 and XCode projects instead.


# Usage

The easiest way to run this server is simply to run it on the command-line
with one or more DNS zone-files:

	# robdns example.zone

Zone-files are in standard format, and must start with an SOA record. Most all
record formats are supported. This example will start responding to DNS
requests on port 53 for the indicated zones. You can test that it's working
by doing something like

	$ dig chaos txt version.bind @localhost +short
    
You should get back the version string of `robdns/1`.

However, this is not the correct way to run the software. The primary feature
of the software is that it contains its own network stack. The real way to
run this is:

    # robdns example.zone dna0 192.168.1.222

In this example, the software will use the PF_RING drivers to bypass the 
operating system, and respond to queries at rates of millions-per-second
(depending upon number of CPUs and other factors).


# Feature status

Most RRs are now parsed.


# Authors

This tool created by Robert Graham:
email: robert_david_graham@yahoo.com
twitter: @ErrataRob






