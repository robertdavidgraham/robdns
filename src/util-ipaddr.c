#include "util-ipaddr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>


#ifndef UNUSEDPARM
#define UNUSEDPARM(seed)
#endif

#define false 0
#define true 1

static unsigned
hexval(int c)
{
	if ('0'<=c && c<='9')
		return (unsigned)(c-'0');
	else if ('a'<=c && c<='f')
		return (unsigned)(c-'a'+10);
	else if ('A'<=c && c<='F')
		return (unsigned)(c-'A'+10);
	else
		return 0;
}

/* Set the offset to the character that caused the error before returning */
#define RETURN_ERR(n) *offset=i,n

/****************************************************************************
 * Format an IPv6 address.
 * Example:
 *  3ffe:ffff:101::230:6eff:fe04:d9ff
 * 
 * NOTE: The symbol :: is a special syntax that can be used as a 
 * shorthand way of representing multiple 16-bit groups of 
 * contiguous 0’s (zeros). The :: can appear anywhere in the address; 
 * however it can only appear once in the address.
 *
 ****************************************************************************/
void
format_ipv6_address(char *buf, size_t sizeof_buf, const void *v_addr)
{
    const unsigned char *px = (const unsigned char *)v_addr;
    unsigned buf_offset = 0;
    unsigned i;
	unsigned zeroes_max_length = 0;
	unsigned zeroes_offset = 0xFFFF;

	/* Make sure we have enough space for the printed version */
    if (sizeof_buf < 41 || v_addr == NULL) {
        if (sizeof_buf > 4) {
            memcpy(buf, "err\0", 4);
        } else if (sizeof_buf > 1)
            buf[0] = '\0';
        else
            ;
        return;
    }

	/* Go through and find the longest stream of zeroes */
	for (i=0;  i<16;  i+=2) {
		if (px[i] == 0 && px[i+1] == 0) {
			unsigned length = 0;
			unsigned j;

			/* Find out how long this stream of 0000 goes for */
			for (j=i;  j<16;  j+=2) {
				unsigned num = px[j]<<8 | px[j+1];
				if (num == 0)
					length++;
				else
					break;
			}

			/* Is this the longest such string? */
			if (zeroes_max_length < length) {
				zeroes_max_length = length;
				zeroes_offset = i;
			}
		}
	}


	/*
	 * for all 2-byte numbers
	 *   print the 2-byte number :
	 */
    for (i=0;  i<16;  i+=2) {
		if (i == zeroes_offset) {
            buf[buf_offset++] = ':';
            while (i+2 < 16 && (px[i+2]<<8 | px[i+3]) == 0)
                i += 2;
            if (i+2 == 16)
                buf[buf_offset++] = ':';
		} else {
			unsigned nibble[4];
            if (i != 0)
                buf[buf_offset++] = ':';
			nibble[0] = (px[i+0]>>4)&0xF;
			nibble[1] = (px[i+0]>>0)&0xF;
			nibble[2] = (px[i+1]>>4)&0xF;
			nibble[3] = (px[i+1]>>0)&0xF;

			if (nibble[0])
		        buf[buf_offset++] = "0123456789abcdef"[nibble[0]];
			if (nibble[0] || nibble[1])
	            buf[buf_offset++] = "0123456789abcdef"[nibble[1]];
			if (nibble[0] || nibble[1] || nibble[2])
	            buf[buf_offset++] = "0123456789abcdef"[nibble[2]];
            buf[buf_offset++] = "0123456789abcdef"[nibble[3]];
        }
    }

	/* nul terminate */
    buf[buf_offset] = '\0';
}


/****************************************************************************
 * Prints an IPv4 adddress into a string.
 * Example:
 *		"192.168.0.0/16"
 *		"24.184.82.203"
 * This formats the integers directly without using sprintf()
 ****************************************************************************/
void
format_ipv4_address(char *buf, size_t sizeof_buf, const void *v_addr)
{
	const unsigned char *addr = (const unsigned char *)v_addr;
	unsigned i;
	unsigned d = 0;

	/* leave enough space for NUL termination */
	sizeof_buf--;

	/* 'for all 4 numbers'
	 *   'print the numbers manually without sprintf()' */
	for (i=0; i<4; i++) {
		unsigned number = addr[i];
		if (number == 0) {
			if (d<sizeof_buf)
				buf[d++] = '0';
		} else {
			char c2;
			c2 = (number % 10) + '0';
			number /= 10;
			if (number) {
				char c1;
				c1 = (number % 10) + '0';
				number /= 10;
				if (number) {
					int c0;
					c0 = number + '0';
					if (d<sizeof_buf)
						buf[d++] = (char)c0;
				}
				if (d<sizeof_buf)
					buf[d++] = c1;
			}
			if (d<sizeof_buf)
				buf[d++] = c2;
		}
		if (i < 3 && d<sizeof_buf) {
			buf[d++] = '.';
		}
	}

	/* nul terminate the string */
	if (d<=sizeof_buf)
		buf[d++] = '\0';
	else
		buf[sizeof_buf] = '\0';
}

/****************************************************************************
 * Format an address. Right now, we are using this for unit testing, to
 * make sure that the parsed address matches the original string.
 ****************************************************************************/
static void
format_address(	char *buf, size_t sizeof_buf, 
				const void *v_addr, size_t sizeof_addr, 
				unsigned prefix_length)
{
	/*
	 * IPv4 or IPv6
	 */
	if (sizeof_addr == 4) {
		format_ipv4_address(buf, sizeof_buf, v_addr);
		if (prefix_length != ~0 && prefix_length > 32)
			prefix_length = (unsigned)~0;
        if (prefix_length == 32)
            prefix_length = (unsigned)~0;
	} else if (sizeof_addr == 16) {
		format_ipv6_address(buf, sizeof_buf, v_addr);
		if (prefix_length != ~0 && prefix_length > 128)
			prefix_length = (unsigned)~0;
        if (prefix_length >= 128)
            prefix_length = (unsigned)~0;
	} else if (sizeof_buf > 0)
		buf[0] = '\0';

	/*
	 * /CIDR prefix length
	 */
	if (prefix_length != ~0) {
		size_t d = strlen(buf);
		char c2;
		unsigned number = prefix_length;
		
		/* slash */
		if (d<sizeof_buf)
			buf[d++] = '/';

		c2 = (number % 10) + '0';
		number /= 10;
		if (number) {
			char c1;
			c1 = (number % 10) + '0';
			number /= 10;
			if (number) {
				int c0;
				c0 = number + '0';
				if (d<sizeof_buf)
					buf[d++] = (char)c0;
			}
			if (d<sizeof_buf)
				buf[d++] = c1;
		}
		if (d<sizeof_buf)
			buf[d++] = c2;

		if (d<sizeof_buf)
			buf[d] = '\0';
		else if (sizeof_buf)
			buf[sizeof_buf-1] = '\0';
	}
}

void
format_ip_address(	char *buf, size_t sizeof_buf, 
				const void *v_addr, unsigned version, 
				unsigned prefix_length)
{
    format_address(buf, sizeof_buf, v_addr, (version==4)?4:16, prefix_length);
}


/****************************************************************************
 * Attempts to parse an IPv4 address out of the input stream.
 * If successful, it returns 'true', moves the 'offset' forward to the next
 * character after the address, and fills in the 'ip' structure.
 * If unsuccessful, it returns 'false', does not change 'offset', but
 * may or may not change some fields in 'ip'.
 ****************************************************************************/
int
parse_ipv4_address(const char *px, unsigned *offset, size_t length, struct ParsedIpAddress *ip)
{
    unsigned tmp_offset = 0;
    unsigned i;
    unsigned j;

    if (offset == NULL && length == 0) {
        offset = &tmp_offset;
        length = strlen(px);
    } else if (offset == NULL) {
        offset = &tmp_offset;
    }


    i = *offset;


    /* Provisionally set this to IPv4 for this function (IPv6 parser will 
	 * set this likewise to IPv6 if it succeeds) */
    ip->version = 4;

    /* If no /CIDR spec is found, assume 32-bits for IPv4 addresses */
    ip->prefix_length = 32;

	/* Parse the 4 numbers in an IPv4 address */
    for (j=0; j<4; j++) {
        unsigned num = 0;
        unsigned k;

        /* Each of the 4 numbers must start with a digit */
        if (i>=length || !isdigit(px[i]&0xFF))
            return RETURN_ERR(false);

        /* Parse the number */
        for (k=0; k<3 && i+k < length && isdigit(px[i+k]&0xFF); k++)
            num = num * 10 + (px[i+k]-'0');
        i += k;
        if (num > 255)
            return RETURN_ERR(false);
        ip->address[j] = (unsigned char)num;
        
        /* Make sure the next character is a dot */
        if (j<3) {
			if (i<length && px[i] == '/') {
				/* Allow truncated addresses, like "10/8" or "192.168/16" */
				while (j<3)
					ip->address[++j] = 0;
			} else if (i>=length || px[i] != '.') {
	            return RETURN_ERR(false);
			} else
	            i++;
        }
    }

    /* Check for optional CIDR field */
    if (i<length && px[i] == '/') {
        unsigned n = 0;
        
        i++;

        if (i>=length || !isdigit(px[i]*0xFF))
            return RETURN_ERR(false);

        n = px[i] - '0';
        i++;

        if (i<length && isdigit(px[i]&0xFF)) {
            n = n * 10 + px[i] - '0';
            i++;
        }

        if (n > 32)
            return RETURN_ERR(false);
        else
            ip->prefix_length = (unsigned char)n;
    }

    *offset = i;
    return true;
}


/****************************************************************************
 * Parse an IPv6 address
 *
 * Returns '0' if successful, some other value otherwise.
 *
 * Example:
 *  3ffe:ffff:101::230:6eff:fe04:d9ff
 * 
 * NOTE: The symbol :: is a special syntax that can be used as a 
 * shorthand way of representing multiple 16-bit groups of 
 * contiguous 0’s (zeros). The :: can appear anywhere in the address; 
 * however it can only appear once in the address.
 *
 ****************************************************************************/
static int
parse_ipv6_address(const char *px, unsigned *offset, size_t length, struct ParsedIpAddress *ip)
{
	unsigned i = *offset;
	unsigned is_bracket_seen = 0;
	unsigned elision_offset = (unsigned)~0;
	unsigned d = 0;

	/* Provisionally set this to IPv6 */
	ip->version = 6;

    /* If no /CIDR spec is found, assume 128-bits for IPv6 addresses */
    ip->prefix_length = 128;

	/* Remove leading whitespace */
	while (i<length && isspace(px[i]&0xFF))
		i++;

	/* If the address starts with a '[', then remove it */
	if (i<length && px[i] == '[') {
		is_bracket_seen = 1;
		i++;
		while (i<length && isspace(px[i]&0xFF))
			i++;
	}

	/* Now parse all the numbers out of the stream */
	while (i<length) {
		unsigned j;
		unsigned number = 0;

		/* Have we found all 128-bits? */
		if (d >= 16)
			break;

		/* Is there an elision/compression of the address? */
		if (px[i] == ':') {
			elision_offset = d;
			i++;
			continue;
		}

		/* Parse the hex digits into a 2-byte number */
		j=0;
		while (i<length) {
			if (j >= 4)
				break;
			if (px[i] == ':')
				break; /* early exit due to leading nuls */
			if (!isxdigit(px[i]&0xFF)) {
                return RETURN_ERR(false);
				break; /* error */
			}

			number <<= 4;
			number |= hexval(px[i++]);
			j++;
		}

		/* If no hex digits were processed */
		if (j == 0)
			break;

		/* We have a 2-byte number */
		ip->address[d+0] = (unsigned char)(number>>8);
		ip->address[d+1] = (unsigned char)(number>>0);
		d += 2;

		/* See if we have the normal continuation */
		if (i<length && px[i] == ':') {
			i++;
			continue;
		}

		/* Or, see if we have reached the trailing ']' character */
		if (i<length && is_bracket_seen && px[i] == ']') {
			i++; /* skip ']' */
			is_bracket_seen = false;
			break;
		}

		/* We have parsed all the address we are looking for. Therefore, stop
		 * parsing at this point */
		if (d == 16)
			break;

		/* Is there an ellision in this address? If so, break at this point */
		if (elision_offset != (unsigned)(~0))
			break;

		/* See if we have reached the end of the address. This is a prem*/
		if (i == length)
			break;

		/* Some unknown character is seen, therefore return an
		 * error */
		return RETURN_ERR(false);
	}

	/* Insert zeroes where numbers were removed */
	if (elision_offset != ~0) {
		if (d == 16) {
			/* oops, there was no elision, this is an error */
			return RETURN_ERR(false);
		}

		memmove(ip->address + elision_offset + 16 - d, 
				ip->address + elision_offset,
				d - elision_offset);
		memset(	ip->address + elision_offset,
				0,
				16-d);
	}

    /* Check for optional CIDR field */
    if (i<length && px[i] == '/') {
        unsigned n = 0;
        
        i++;

        if (i>=length || !isdigit(px[i]&0xFF))
            return RETURN_ERR(false);

        n = px[i] - '0';
        i++;

        if (i<length && isdigit(px[i]&0xFF)) {
            n = n * 10 + px[i] - '0';
            i++;
        }

        if (n > 128)
            return RETURN_ERR(false);
        else
            ip->prefix_length = (unsigned char)n;
    }

    *offset = i;
    return true;
}


/****************************************************************************
 * Parses an IP address (IPv4 or IPv6). This function automatically
 * determines whether this is v4 or v6.
 * @param px [IN]
 *		A text string containing an IP address, followed by additional
 *		text that this function ignores.
 * @param offset [IN/OUT]
 *		On input, the offset from the start of the string where this IP
 *		address starts. On output, the offset of the first byte after
 *		this IP address, or if an error occurred, the offset of the
 *		offending character. For errors, this allows a GCC-style
 *		error message that points to the precise character on the line
 *		causing the syntax error.
 * @param length [IN]
 *		The length of the line. Also, the maximum value possible for
 *		(*offset)
 * @param ip [OUT]
 *		The parsed IP address. This includes the binary addresses itself
 *		(in network byte order) as well as the version, either the number
 *		4 or 6.
 ****************************************************************************/
int
parse_ip_address(const char *px, unsigned *offset, size_t length, struct ParsedIpAddress *ip)
{
	unsigned i;
    unsigned tmpoffset = 0;

    if (offset == 0 && length == 0) {
        offset = &tmpoffset;
        length = strlen(px);
    }

	ip->version = 0;

	/* First, figure out if this is an IPv4 or IPv6 address by searching
	 * forward to the first character that belongs to one, but not the other
	  * IPv4: ".0123456789"
	  * IPv6: ":0123456789abcdef"
	  */
	for (i=*offset;  i<length && ip->version==0;  i++) {
		switch (px[i]) {
		case '0': case '1': case '2': case '3': case '4': 
		case '5': case '6': case '7': case '8': case '9':
			break;
		case 'a': case 'A': case 'b': case 'B': case 'c': case 'C':
		case 'd': case 'D': case 'e': case 'E': case 'f': case 'F':
			ip->version = 6;
			break;
		case '.':
			ip->version = 4;
			break;
		case ':':
			ip->version = 6;
			break;
		case '/':
			ip->version = 4;
			break; /* Truncated IPv4 address, like "10/8" or "192.168/16" */
		}
	}

	/*
	 * Now parse the address
	 */
	if (ip->version == 6)
		return parse_ipv6_address(px, offset, length, ip);
	else
		return parse_ipv4_address(px, offset, length, ip);
}


/****************************************************************************
 ****************************************************************************/
static unsigned
parse_address(	void *v_dst,		size_t sizeof_dst,
				const char *src,	size_t sizeof_src,
				unsigned *prefix_length)
{
	struct ParsedIpAddress ip;
	int result;
	unsigned offset = 0;


	if (sizeof_src == ~0)
		sizeof_src = strlen(src);

	result = parse_ip_address(src, &offset, sizeof_src, &ip);
	if (result == false)
		return (unsigned)-1;


	if (ip.version == 4) {
		if (sizeof_dst >= 4)
			memcpy(v_dst, ip.address, 4);
		if (ip.prefix_length < 32)
			*prefix_length = ip.prefix_length;
	} else if (ip.version == 6) {
		if (sizeof_dst >= 16)
			memcpy(v_dst, ip.address, 16);
		if (ip.prefix_length < 128)
			*prefix_length = ip.prefix_length;
	} else
		return (unsigned)-1;

	return ip.version;
}

/****************************************************************************
 ****************************************************************************/
unsigned
parse_address_selftest()
{
	static const struct TestAddresses {
		const char *input;
		const char *output;
	} test_addresses[] = {
		{"2620:0:2d0:200::8",0},
		{"3ffe:ffff:101::230:6eff:fe04:d9ff",0},
		{"2001:db8:ac10:fe01::",0}, /* sample from Wikipedia */
		{"ff02::1",0}, /* multicast */
		{"2001::4137:9e76:1083:1155:f5ff:ffd0",0}, /* taredo address */
		{"2001:db8:85a3::8a2e:370:7334",0},
		{"::1",0}, /* localhost loopback address */
		{"2001:db8:85a3:8d3:1319:8a2e:370:7348",0},
		{"2005:123:456:789:ab:cd:e:f/64",0},
		{"10/8", "10.0.0.0/8"},
		{"192.168/16", "192.168.0.0/16"},
		{"255.255.255.255",0},
		{"66.249.72.112",0},
		{"fd6a:d720:39c7:973a::/64",0}, /* from http://www.simpledns.com/private-ipv6.aspx */
		{"74.238.146.110",0},
		{"2001::/32",0},
		{0}
	};
	unsigned i;

	UNUSEDPARM(seed);

	/* 
	 * Parse strings, then format the address back to strings.
	 * Make sure they are equal.
	 */
	for (i=0; test_addresses[i].input; i++) {
		unsigned char address[16];
		char string[64];
		unsigned version;
		unsigned prefix_length = (unsigned)~0;
		const char *expected_output;

		/* parse the IPv6 address */
		version = parse_address(address, sizeof(address), test_addresses[i].input, (size_t)~0, &prefix_length);
		if (version == (unsigned)-1) {
			fprintf(stderr, "%s:%d:#%u: selftest failed\n", __FILE__, __LINE__, i);
			return 1;
		}

		/* now format the address */
		format_address(string, sizeof(string), address, (version==4)?4:16, prefix_length);

		expected_output = test_addresses[i].output;
		if (expected_output == NULL)
			expected_output = test_addresses[i].input;

		if (strcmp(expected_output, string) != 0) {
			fprintf(stderr, "%s:%d:%u: selftest failed\n", __FILE__, __LINE__, i);
			return 1;
		}
	}

	return 0;
}




