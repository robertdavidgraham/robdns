#ifndef RULE_PARSE_ADDRESS_H
#define RULE_PARSE_ADDRESS_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdint.h>

/**
 * An IP (version 4 or version 6) address that we parsed out of a Snort 
 * rule
 */
struct ParsedIpAddress {
    unsigned char address[16];		/* big enough for IPv6 and IPv4 */
    unsigned char prefix_length;	/* CIDR-style /prefix */
    unsigned char version;			/* '4' or '6' */
};

/* Set the offset to the character that caused the error before returning */
#define RETURN_ERR(n) *offset=i,n

/**
 * Attempt to parse an address (IPv4 or IPv6) from the input, including a CIDR-style
 * prefix at the end.
 * @params
 *		px
 *			Points to the input text field.
 *		*offset [IN/OUT]
 *			The starting offset in the text field were we should parse the address,
 *			and after the function, points to the first character after the address,
 *			or in the case of error, the character that caused the error.
 *		length
 *			The length of the entire text field, which will likely be much longer
 *			than the address. There is likely more text after the address which
 *			other parses will deal with.
 *		ip [OUT]
 *			The returned IP address, which also includes the version number and
 *			prefix. If no prefix information (e.g. "/8") was included with the
 *			address, then the prefix will be the length of the entire address
 *			(32 bits for IPv4, 128 bits for IPv6).
 * @return
 *		Returns 'true' if a valid address is found, and positions '*offset' to point
 *		to the next character after the address.
 *		Returns 'false' if a error occurs, and positions '*offset' to point to the
 *		character at fault.
 */
int
parse_ip_address(const char *px, unsigned *offset, size_t length, struct ParsedIpAddress *ip);

void
format_ip_address(	char *buf, size_t sizeof_buf, 
				const void *v_addr, unsigned version, 
				unsigned prefix_length);

void
format_ipv6_address(char *buf, size_t sizeof_buf, const void *v_addr);

/**
 * Does a quick unit test of the address parser. Returns '0' if everything is ok, and
 * some other number if there was a problem.
 */
unsigned
parse_ip_selftest();


int parse_ipv4_address(const char *px, unsigned *offset, size_t length, struct ParsedIpAddress *ip);

#ifdef __cplusplus
}
#endif
#endif
