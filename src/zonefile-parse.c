#define EVIL_KLUDGES 
#include "zonefile-parse.h"
#include "zonefile-dfa.h"
#include "zonefile-rr.h"
#include "zonefile-fields.h"
#include "string_s.h"
#include "logger.h"
#include "util-realloc2.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include "success-failure.h"
#include "unusedparm.h"

#include "thread-atomic.h"
#include "pixie-timer.h"


#if defined(EVIL_KLUDGES)
#if defined(WIN32)
//#include <intrin.h>
#endif
#endif


int is_verbose = 0;

/****************************************************************************
 ****************************************************************************/
static const struct {
	const char *name;
	unsigned value;
} types[] = {
{"A",		TYPE_A},	/*  1	RFC 1035[1]	address record	Returns a 32-bit IPv4 address, most commonly used to map hostnames to an IP address of the host, but also used for DNSBLs, storing subnet masks in RFC 1101, etc.*/
{"AAAA",	TYPE_AAAA}, /*  28	RFC 3596[2]	IPv6 address record	Returns a 128-bit IPv6 address, most commonly used to map hostnames to an IP address of the host.*/
{"AFSDB",	TYPE_AFSDB}, /*	18	RFC 1183	AFS database record	Location of database servers of an AFS cell. This record is commonly used by AFS clients to contact AFS cells outside their local domain. A subtype of this record is used by the obsolete DCE/DFS file system. */
{"APL",		TYPE_APL}, /*	42	RFC 3123	Address Prefix List	Specify lists of address ranges, e.g. in CIDR format, for various address families. Experimental. */
{"CAA",		TYPE_CAA}, /*	257	RFC 6844	Certification Authority Authorization	CA pinning, constraining acceptable CAs for a host/domain */
{"CERT",	TYPE_CERT}, /*	37	RFC 4398	Certificate record	Stores PKIX, SPKI, PGP, etc. */
{"CNAME",	TYPE_CNAME}, /*	5	RFC 1035[1]	Canonical name record	Alias of one name to another: the DNS lookup will continue by retrying the lookup with the new name. */
{"DHCID",	TYPE_DHCID}, /*	49	RFC 4701	DHCP identifier	Used in conjunction with the FQDN option to DHCP */
{"DLV",		TYPE_DLV}, /*	32769	RFC 4431	DNSSEC Lookaside Validation record	For publishing DNSSEC trust anchors outside of the DNS delegation chain. Uses the same format as the DS record. RFC 5074 describes a way of using these records. */
{"DNAME",	TYPE_DNAME}, /*	39	RFC 2672	delegation name	DNAME creates an alias for a name and all its subnames, unlike CNAME, which aliases only the exact name in its label. Like the CNAME record, the DNS lookup will continue by retrying the lookup with the new name. */
{"DNSKEY",	TYPE_DNSKEY}, /*48	RFC 4034	DNS Key record	The key record used in DNSSEC. Uses the same format as the KEY record. */
{"DS",		TYPE_DS}, /*	43	RFC 4034	Delegation signer	The record used to identify the DNSSEC signing key of a delegated zone */
{"HIP",		TYPE_HIP}, /*	55	RFC 5205	Host Identity Protocol	Method of separating the end-point identifier and locator roles of IP addresses. */
{"HINFO",   TYPE_HINFO}, /* 13  RFC 1035    Host Information */
{"IPSECKEY",TYPE_IPSECKEY}, /*	45	RFC 4025	IPsec Key	Key record that can be used with IPsec */
{"KEY",		TYPE_KEY}, /*	25	RFC 2535[3] and RFC 2930[4]	key record	Used only for SIG(0) (RFC 2931) and TKEY (RFC 2930).[5] RFC 3445 eliminated their use for application keys and limited their use to DNSSEC.[6] RFC 3755 designates DNSKEY as the replacement within DNSSEC.[7] RFC 4025 designates IPSECKEY as the replacement for use with IPsec.[8] */
{"KX",		TYPE_KX}, /*	36	RFC 2230	Key eXchanger record	Used with some cryptographic systems (not including DNSSEC) to identify a key management agent for the associated domain-name. Note that this has nothing to do with DNS Security. It is Informational status, rather than being on the IETF standards-track. It has always had limited deployment, but is still in use. */
{"LOC",		TYPE_LOC}, /*	29	RFC 1876	Location record	Specifies a geographical location associated with a domain name */
{"MX",		TYPE_MX}, /*	15	RFC 1035[1]	mail exchange record	Maps a domain name to a list of message transfer agents for that domain */
{"NAPTR",	TYPE_NAPTR}, /*	35	RFC 3403	Naming Authority Pointer	Allows regular expression based rewriting of domain names which can then be used as URIs, further domain names to lookups, etc. */
{"NS",		TYPE_NS}, /*	2	RFC 1035[1]	name server record	Delegates a DNS zone to use the given authoritative name servers */
{"NSEC",	TYPE_NSEC}, /*	47	RFC 4034	Next-Secure record	Part of DNSSEC—used to prove a name does not exist. Uses the same format as the (obsolete) NXT record. */
{"NSEC3",	TYPE_NSEC3}, /*	50	RFC 5155	NSEC record version 3	An extension to DNSSEC that allows proof of nonexistence for a name without permitting zonewalking */
{"NSEC3PARAM",TYPE_NSEC3PARAM}, /*	51	RFC 5155	NSEC3 parameters	Parameter record for use with NSEC3 */
{"PTR",		TYPE_PTR}, /*	12	RFC 1035[1]	pointer record	Pointer to a canonical name. Unlike a CNAME, DNS processing does NOT proceed, just the name is returned. The most common use is for implementing reverse DNS lookups, but other uses include such things as DNS-SD. */
{"RRSIG",	TYPE_RRSIG}, /*	46	RFC 4034	DNSSEC signature	Signature for a DNSSEC-secured record set. Uses the same format as the SIG record. */
{"RP",		TYPE_RP}, /*	17	RFC 1183	Responsible person	Information about the responsible person(s) for the domain. Usually an email address with the @ replaced by a . */
{"SIG",		TYPE_SIG}, /*	24	RFC 2535	Signature	Signature record used in SIG(0) (RFC 2931) and TKEY (RFC 2930).[7] RFC 3755 designated RRSIG as the replacement for SIG for use within DNSSEC.[7] */
{"SOA",		TYPE_SOA}, /*	6	RFC 1035[1]	start of [a zone of] authority record	Specifies authoritative information about a DNS zone, including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone. */
{"SPF",		TYPE_SPF}, /*	99	RFC 4408	Sender Policy Framework	Specified as part of the SPF protocol as an alternative to of storing SPF data in TXT records. Uses the same format as the earlier TXT record. */
{"SRV",		TYPE_SRV}, /*	33	RFC 2782	Service locator	Generalized service location record, used for newer protocols instead of creating protocol-specific records such as MX. */
{"SSHFP",	TYPE_SSHFP}, /*	44	RFC 4255	SSH Public Key Fingerprint	Resource record for publishing SSH public host key fingerprints in the DNS System, in order to aid in verifying the authenticity of the host. RFC 6594 defines ECC SSH keys and SHA-256 hashes. See the IANA SSHFP RR parameters registry for details. */
{"TA",		TYPE_TA}, /*	32768	N/A	DNSSEC Trust Authorities	Part of a deployment proposal for DNSSEC without a signed DNS root. See the IANA database and Weiler Spec for details. Uses the same format as the DS record. */
{"TKEY",	TYPE_TKEY}, /*	249	RFC 2930	secret key record	A method of providing keying material to be used with TSIG that is encrypted under the public key in an accompanying KEY RR.[9] */
{"TLSA",	TYPE_TLSA}, /*	52	RFC 6698	TLSA certificate association	A record for DNS-based Authentication of Named Entities (DANE). RFC 6698 defines "The TLSA DNS resource record is used to associate a TLS server certificate or public key with the domain name where the record is found, thus forming a 'TLSA certificate association'". */
{"TSIG",	TYPE_TSIG}, /*	250	RFC 2845	Transaction Signature	Can be used to authenticate dynamic updates as coming from an approved client, or to authenticate responses as coming from an approved recursive name server[10] similar to DNSSEC. */
{"TXT",		TYPE_TXT}, /* */

{";",		TYPE_COMMENT}, /* */
    

{"IN",		0x10000 | CLASS_IN}, /* */
{"CS",		0x10000 | CLASS_CS}, /* */
{"CH",		0x10000 | CLASS_CH}, /* */
{"HS",		0x10000 | CLASS_HS}, /* */

{"TYPE",	0x20000}, /* */

{0,0}
};

/****************************************************************************
 ****************************************************************************/
void build_type_dfa(struct MyDFA *dfa)
{
	unsigned i;

	mydfa_init(dfa);

    
	/* first go through and add all the symbols */
	for (i=0; types[i].name; i++) {
		mydfa_add_symbols(dfa, (const unsigned char*)types[i].name, (unsigned)strlen(types[i].name));
	}

	/* now add all the patterns */
	for (i=0; types[i].name; i++) {
		mydfa_add_pattern(dfa, (const unsigned char*)types[i].name, (unsigned)strlen(types[i].name), types[i].value);
	}


	assert(mydfa_selftest(dfa, " IN 8\n", 0x10000|CLASS_IN));
	assert(mydfa_selftest(dfa, "IN SOA\n", 0x10000|CLASS_IN));
	assert(mydfa_selftest(dfa, "\t\t\t\tNS   \r\n", TYPE_NS));

	return;
}

/****************************************************************************
 ****************************************************************************/
void build_variable_dfa(struct MyDFA *dfa)
{
	unsigned i;
	const char *variables[] = {
		"OOOOOO",
		"ORIGIN",
		"TTL",
		"INCLUDE",
		0
	};

	mydfa_init(dfa);

    
	/* first go through and add all the symbols */
	for (i=0; variables[i]; i++) {
		mydfa_add_symbols(dfa, (const unsigned char*)variables[i], (unsigned)strlen(variables[i]));
	}

	/* now add all the patterns */
	for (i=0; variables[i]; i++) {
		mydfa_add_pattern(dfa, (const unsigned char*)variables[i], (unsigned)strlen(variables[i]), i);
	}

	assert(mydfa_selftest(dfa, " TTL \r\t\n", 2));
	assert(mydfa_selftest(dfa, "ORIGIN x", 1));

	return;
}


/****************************************************************************
 ****************************************************************************/
const char *
name_of_type(unsigned type)
{
	unsigned i;
    static char buf[64];
	

	for (i=0; types[i].name; i++) {
		if (types[i].value == type)
			return types[i].name;
	}

    sprintf_s(buf, sizeof(buf), "TYPE%u", type);

	return buf;
}









/****************************************************************************
 ****************************************************************************/
#define ISSPACE(c) (c == ' ' || c == '\t')
static unsigned char _isdomainchar[256];
#define isdomainchar(c) _isdomainchar[c]
static struct MyDFA _type_dfa[1];
static struct MyDFA _variable_dfa[1];

static void isdomainchar_init(void)
{
	unsigned i;
	int c;

	memset(_isdomainchar, 0, sizeof(_isdomainchar));

	for (i=0; i<26; i++) {
		c = 'A' + i;
		_isdomainchar[c] = 1;
		c = 'a' + i;
		_isdomainchar[c] = 1;
	}
	for (i=0; i<10; i++) {
		c = '0' + i;
		_isdomainchar[c] = 1;
	}
	c = '-';
	_isdomainchar[c] = 1;

	assert(isdomainchar('n'));
	assert(isdomainchar('-'));
	assert(isdomainchar('6'));
	assert(!isdomainchar('&'));

}


/****************************************************************************
 ****************************************************************************/
void
x_parse_domain(struct ZoneFileParser *parser, 
               const unsigned char *__restrict buf, 
               unsigned *__restrict offset, 
               unsigned length)
{
    struct DomainBuilder *domain = &parser->rr_domain;
	unsigned i;
	unsigned s = parser->s2;
	unsigned char *name = domain->name;
	unsigned label = domain->label;
	unsigned name_length = domain->length;
	
	enum {
		$START,
		$DOMAIN=1, 
		$DOMAIN_ESC0, $DOMAIN_ESC1, $DOMAIN_ESC2,
		$END,
		$SPACE,
		$PARSE_ERROR,
	};

	for (i=*offset; i<length; i++) {
	register unsigned char c = buf[i];
	switch (s) {
	case $START:
		name_length = 1;	/* minimum of one label, even for empty domain */
		name[0] = 0;		/* first label starts at zero */
		label = 0;			/* str[0] is the first label */
		if (c == '@') {
			name_length = 0;
			s = $SPACE;
			continue;
		}
		s = $DOMAIN;

		/* fall through */
	case $DOMAIN:
	case_domain:
		if (name_length >= 256) {
			parse_err(parser, "domain name exceeds 256 bytes\n");
			s = $PARSE_ERROR;
			continue;
		} else if (c == ' ' || c == '\t' || c == '\r') {
			s = $SPACE;
			continue;
		} else if (c == '\n') {
			goto end;
		} else if (name[label] >= 64) {
			parse_err(parser, "domain label exceeds 63 bytes\n");
			s = $PARSE_ERROR;
			continue;
		} else if (c == '.') {
			do_label:
			label += 1 + name[label];
			name[label] = 0;		/* next label starts at zero */
			name_length++;			/* still increment length even though this a dot */
            domain->is_absolute = 1;
			continue;
		} else if (c == '\\') {
			s = $DOMAIN_ESC0;
			continue;
		} else {
			/*unsigned j = i;
			unsigned len;
			for (j=i; j<length && isdomainchar(buf[j]); j++)
				;
			len = j-i;
			memcpy(name+name_length, buf+i, len);
			name_length += len;
			name[label] += len;
			i += len-1;
			*/
			domain->is_absolute = 0;
			name[name_length++] = c;
			name[label]++;
			i++;
			c = buf[i];
			while (isdomainchar(c) && i < length) {
				name[name_length++] = c;
				name[label]++;
				c = buf[++i];
			}
			if (i<length && c == '.')
				goto do_label;
			i--;
			
			

			/*if (i < length && 'A' <= buf[i+1] && buf[i+1] <= 'Z') {
				c = buf[++i];
				goto zzz;
			}*/
			continue;
		}
		break;
	case $DOMAIN_ESC0:
		if ('0' <= c && c <= '9') {
			parser->substring_esc = c - '0';
			s = $DOMAIN_ESC1;
			continue;
		} else if (c == '.') {
			/* length checks were done above */
			name[name_length++] = c;
			name[label]++;
			s = $DOMAIN;
			continue;
		}
		break;
	case $DOMAIN_ESC1:
		if ('0' <= c && c <= '9') {
			parser->substring_esc *= 10;
			parser->substring_esc = c - '0';
			s = $DOMAIN_ESC2;
			continue;
		} else {
			name[name_length++] = (unsigned char)parser->substring_esc;
			name[label]++;
			s = $DOMAIN;
			goto case_domain;
		}
		break;
	case $DOMAIN_ESC2:
		if ('0' <= c && c <= '9') {
			parser->substring_esc *= 10;
			parser->substring_esc = c - '0';
			name[name_length++] = (unsigned char)parser->substring_esc;
			name[label]++;
			s = $DOMAIN;
			continue;
		} else {
			name[name_length++] = (unsigned char)parser->substring_esc;
			name[label]++;
			s = $DOMAIN;
			goto case_domain;
		}
		break;

	case $SPACE:
		while (i<length && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\r'))
			i++;
		if (i<length)
			goto end;

	case $PARSE_ERROR:
		while (i<length && !isspace(buf[i]))
			i++;
		break;
	}
	}

end:
	domain->label = (unsigned char)label;
	domain->length = (unsigned char)name_length;
	parser->s2 = s;
	*offset = i;
}




/****************************************************************************
 ****************************************************************************/
unsigned
x_parse_type(struct ZoneFileParser *parser, const unsigned char *buf, unsigned *offset, unsigned length)
{
	unsigned type = 0;

again:
	switch (parser->s2) {
	case 0x20000:
		while (*offset < length && '0' <= buf[*offset] && buf[*offset] <= '9') {
			parser->rr_type.result = parser->rr_type.result * 10 + (buf[*offset] - '0');
			(*offset)++;
		}
		if (*offset >= length)
			return 0; /* pause if fragmented */
		parser->s2 = 0x20001;

	case 0x20001:
		while (*offset < length && (buf[*offset]==' '||buf[*offset]=='\t'||buf[*offset]=='\r')) {
			(*offset)++;
		}
		if (*offset >= length)
			return 0; /* pause if fragmented */
		parser->s2 = 0x20002;

	case 0x20002:
		return (unsigned)parser->rr_type.result;

	case 0x20003:
		while (*offset < length && buf[*offset] != '\n')
			(*offset)++;
		if (*offset >= length)
			return 0; /* pause if fragmented */
		if (parser->is_multiline) {
			parser->s2 = 0;
			goto again;
		} else
			return type;

	default:
		type = mydfa_search(parser->type_dfa, &parser->s2, buf, offset, length);
		if (0 < type && type < 0x10000)
			return type;
		else if (type == 0x20000) {
			parser->rr_type.result = 0;
			parser->s2 = 0x20000;
			goto again;
		} else if (*offset >= length) {
			/* reached end of buffer */
			return 0;
		} else if (type == 0xFFFFFFFF) {
			if ('0' <= buf[*offset] && buf[*offset] < '9') {
				parser->rr_type.result = 0;
				parser->s2 = 0x20000;
				goto again;
			}
			
			switch (buf[*offset]) {
			case '(':
				parser->is_multiline = 1;
				(*offset)++;
				parser->s2 = 0;
				goto again;
			case '\n':
				if (parser->is_multiline) {
                    parser->src.line_number++;
					(*offset)++;
					parser->s2 = 0;
					goto again;
				} else
					return type;
			case ')':
				parser->is_multiline = 0;
				(*offset)++;
				parser->s2 = 0;
				goto again;
			case ';':
				parser->s2 = 0x20003;
				goto again;
			default:
				return type;
			}
		} else {
			parse_err(parser, "something bad in doing type\n");
			return (unsigned)-1;
		}
	}
}


/****************************************************************************
 ****************************************************************************/
uint64_t rrsig_expiration_translate(uint64_t number)
{
	if (number >= 20000322173103ULL) {
		struct tm t;
		time_t expiration;
		memset(&t, 0, sizeof(t));
		t.tm_sec = number % 100;
		number /= 100;
		t.tm_min = number % 100;
		number /= 100;
		t.tm_hour = number % 100;
		number /= 100;
		t.tm_mday = number % 100;
		number /= 100;
		t.tm_mon = number % 100 - 1;
		number /= 100;
		t.tm_year = (int)number - 1900;

		expiration = mktime(&t);
		return expiration;
	} else
		return number;
}

/****************************************************************************
 ****************************************************************************/
#define ALIGN(x) (((x)+(7))&~(7))
void mm_integer_start(struct ZoneFileParser *parser)
{
    parser->rr_number = 0;
    parser->s2 = 0;
}
void mm_integer8_end(struct ZoneFileParser *parser)
{
    struct ParsedBlock *block = parser->block;
    uint64_t n = parser->rr_number;
    block->buf[block->offset++] = (unsigned char)(n>>0);
}
void mm_integer16_end(struct ZoneFileParser *parser)
{
    struct ParsedBlock *block = parser->block;
    uint64_t n = parser->rr_number;
    block->buf[block->offset++] = (unsigned char)(n>>8);
    block->buf[block->offset++] = (unsigned char)(n>>0);
}
void mm_integer32_end(struct ZoneFileParser *parser)
{
    struct ParsedBlock *block = parser->block;
    uint64_t n = parser->rr_number;
    block->buf[block->offset++] = (unsigned char)(n>>24);
    block->buf[block->offset++] = (unsigned char)(n>>16);
    block->buf[block->offset++] = (unsigned char)(n>> 8);
    block->buf[block->offset++] = (unsigned char)(n>> 0);
}
void mm_domain_start(struct ZoneFileParser *parser)
{
    parser->rr_domain.is_absolute = 0;
    parser->rr_domain.label = 0;
    parser->rr_domain.length = 1;
    parser->rr_domain.name = parser->block->buf + parser->block->offset;
    parser->rr_domain.name[0] = 0;
    parser->s2 = 0;

    //return &parser->rr_domain;
}

int is_fqdn_terminated(struct DomainPointer domain)
{
    unsigned i;

    for (i=0; i<domain.length; ) {
        if (i == domain.length - 1 && domain.name[i] == 0)
            return 1;
        i += domain.name[i] + 1;
    }
    return 0;
}


void mm_domain_end(struct ZoneFileParser *parser)
{
    struct ParsedBlock *block = parser->block;

    //parser->rr_domain.name[-1] = parser->rr_domain.length;
    block->offset += parser->rr_domain.length;

    if (parser->rr_domain.is_absolute)
        return;

    /*if ((parser->rr_domain.label + 1 == parser->rr_domain.length &
        & parser->rr_domain.name[parser->rr_domain.label] == 0))*/
    {
        /* we have a relative name, so copy the $ORIGIN */
        /* TODO: [VULN]: there should be a vuln here, we need to create
         * a test case to exercise it before fixing it */
        memcpy( block->buf + block->offset,
                block->origin.name,
                block->origin.length);
        block->offset += block->origin.length;
        if (!is_fqdn_terminated(block->origin)) {
            block->buf[block->offset++] = '\0';
        }
    }
}

void mm_buffer_start(struct ZoneFileParser *parser)
{
//        parser->block.rr.txt.text.length = 0;
    parser->rr_buffer.length = 0;
    parser->rr_buffer.line_offset = 0;
    parser->rr_buffer.data = parser->block->buf + parser->block->offset;
    parser->s2 = 0;
}

void mm_buffer_end_line(struct ZoneFileParser *parser)
{
    unsigned i = parser->rr_buffer.line_offset;
    parser->rr_buffer.data[i] = (unsigned char)(parser->rr_buffer.length - i - 1);
}
void mm_buffer_end(struct ZoneFileParser *parser)
{
    parser->block->offset += parser->rr_buffer.length;
}

void mm_base64_start(struct ZoneFileParser *parser)
{
    parser->rr_buffer.length = 0;
    parser->rr_buffer.line_offset = 0;
    parser->rr_buffer.data = parser->block->buf + parser->block->offset;
    parser->s2 = 0;
}
void mm_base64_end(struct ZoneFileParser *parser)
{
    parser->block->offset += parser->rr_buffer.length;
}
void mm_base32_start(struct ZoneFileParser *parser)
{
    parser->rr_buffer.length = 0;
    parser->rr_buffer.line_offset = 0;
    parser->rr_buffer.data = parser->block->buf + parser->block->offset;
    parser->s2 = 0;
}
void mm_base32_end(struct ZoneFileParser *parser)
{
    parser->block->offset += parser->rr_buffer.length;
}
void mm_hex_start(struct ZoneFileParser *parser)
{
    parser->rr_buffer.length = 0;
    parser->rr_buffer.line_offset = 0;
    parser->rr_buffer.data = parser->block->buf + parser->block->offset;
    parser->s2 = 0;
}
void mm_hex_end(struct ZoneFileParser *parser)
{
    parser->block->offset += parser->rr_buffer.length;
}

void mm_typelist_start(struct ZoneFileParser *parser)
{
    parser->rr_typelist.count = 0;
    parser->s2 = 0;
}
void mm_typelist_end(struct ZoneFileParser *parser)
{
    UNUSEDPARM(parser);
}


void mm_ipv6_start(struct ZoneFileParser *parser)
{
    parser->rr_ipv6.length = 0;
    parser->rr_ipv6.ellision = 16;
    parser->s2 = 0;
}
void mm_ipv6_end(struct ZoneFileParser *parser)
{
    unsigned char *px = parser->block->buf + parser->block->offset;
    unsigned zeroes_offset = parser->rr_ipv6.ellision;
    unsigned zeroes_length = 16 - parser->rr_ipv6.length;
    unsigned suffix_length = parser->rr_ipv6.length - parser->rr_ipv6.ellision;
    unsigned suffix_offset = 16 - suffix_length;

    memmove(px + suffix_offset,
            px + zeroes_offset,
            suffix_length);
    memset( px + zeroes_offset,
            0,
            zeroes_length);

    parser->block->offset += 16;
}



/****************************************************************************
 ****************************************************************************/
static void 
x_parse(struct ZoneFileParser *parser, const unsigned char *buf, unsigned length)
{
	unsigned i;
	unsigned s = parser->s;
	struct ParsedBlock *block = parser->block;
	unsigned type;
	enum {
		$LINE_START,
		$TYPE, $TYPE_MORE,
		$DOMAIN, $DOMAIN_SPACE,
		$PARSE_ERROR,
		$EOL,
		$UNTIL_EOL,
		$COMMENT,
		$TTL, $TTL_MORE,
		$VARIABLE, $VARIABLE_TTL,
		$ORIGIN,
		$INCLUDE,

		$RR_SOA, $RR_SOA_DOMAIN, $RR_SOA_CONTACT, $RR_SOA_SERIAL, $RR_SOA_REFRESH, $RR_SOA_RETRY, $RR_SOA_EXPIRE, $RR_SOA_MAX,
		$RR_NS,
		$RR_DNSKEY, $RR_DNSKEY_FLAGS, $RR_DNSKEY_PROTO, $RR_DNSKEY_ALGO, $RR_DNSKEY_KEY,
		$RR_RRSIG, $RR_RRSIG_TYPE, $RR_RRSIG_ALGO, $RR_RRSIG_LABEL, $RR_RRSIG_TTL, 
		$RR_RRSIG_EXPIRE, $RR_RRSIG_INCEPT,	$RR_RRSIG_TAG, $RR_RRSIG_NAME, NAME, $RR_RRSIG_SIGNATURE,
		$RR_NSEC3PARAM, $RR_NSEC3PARAM_ALGO, $RR_NSEC3PARAM_FLAGS, 
		$RR_NSEC3PARAM_ITERATIONS, $RR_NSEC3PARAM_SALT1, $RR_NSEC3PARAM_SALT2, 
		$RR_DS, $RR_DS_TAG, $RR_DS_ALGO, $RR_DS_TYPE, $RR_DS_DIGEST,
		$RR_NSEC3, $RR_NSEC3_ALGO, $RR_NSEC3_FLAGS, $RR_NSEC3_ITERATIONS, 
		$RR_NSEC3_SALT, $RR_NSEC3_HASH, $RR_NSEC3_TYPES,
		$RR_NSEC, $RR_NSEC_DOMAIN, $RR_NSEC_TYPES, 
		$RR_TLSA, $RR_TLSA_USAGE, $RR_TLSA_SELECTOR, $RR_TLSA_TYPE, $RR_TLSA_CERT,
        $RR_SSHFP, $RR_SSHFP_ALGO, $RR_SSHFP_TYPE, $RR_SSHFP_FP,

        $RR_LOC,
		$RR_A,
		$RR_AAAA,
		$RR_TXT, $RR_TXT_START,
		$RR_MX, $RR_MX_DOMAIN,
		$RR_PTR,
		$RR_CNAME,
		$RR_END,
	};


	for (i=0; i<length; i++) {
	
	switch (s) {
	case $RR_END:
        /* IMPORTANT! this is the state where we've finished reading a
         * resource-record.  */
rr_end:
        s = $RR_END;
        block_rr_finish(block);
        if (block->offset + 64*1024 > sizeof(block->buf)
            || parser->is_singlestep)
            block = block_next_to_parse(parser);
		s = $UNTIL_EOL;

	case $UNTIL_EOL:
		if (buf[i] != '\n')
			continue;
		s = $EOL;

	case $EOL:
		if (buf[i] == '\r')
            continue;
        if (buf[i] == '\n') {
            parser->src.line_number++;
			continue;
        }
		s = $LINE_START;

	case $LINE_START:

		switch (buf[i]) {
		case ' ':
		case '\t':
            /* If the line starts with a space, then that means we'll use the
             * the domain-name from the previous line, and just skip to the
             * next field */
            block->buf[block->offset] = (unsigned char)block->domain.length;
            memcpy(&block->buf[block->offset]+1, block->domain.name, block->domain.length);
            block->offset += block->domain.length + 1;
            block->buf[block->offset] = 0xA3;

			s = $TYPE;
            parser->s2 = 0;
               
			continue;
		case '\r':
			s = $EOL;
			continue;
		case '\n':
            parser->src.line_number++;
			s = $LINE_START;
			continue;
		case '$':
			s = $VARIABLE;
			parser->s2 = 0;
			continue;
		case ';':
			s = $COMMENT;
			continue;
        default:
                s = $DOMAIN;
                
                /* Mark the start of the next resource record */
                assert(block->offset_start == block->offset);
                
                parser->s2 = 0;
                parser->rr_domain.name = block->buf + block->offset + 1;
                
		}
        /*
         * Drop down and start processing the next domain name
         */
        
		
	case $DOMAIN:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
            
        /* Save this domain name in case the next line starts with spaces */
        block->domain.name = parser->rr_domain.name;
        block->domain.length = parser->rr_domain.length;
            
        /* this is special logic done for domain-names that you wouldn't
         * normally find when parsing domain-names within RRs */
        block->buf[block->offset] = parser->rr_domain.length;
        block->offset += parser->rr_domain.length + 1;
        block->buf[block->offset] = 0xA3;
        
        s = $TYPE;

	case $TYPE:
		parser->s2 = 0;
		s = $TYPE_MORE;

	case $TYPE_MORE:
		
		type = mydfa_search(parser->type_dfa, &parser->s2, buf, &i, length);
		if (0 < type && type < 0x10000) {
			i--; /* un-parse this character */
			/* We founda TYPE field, as we expected. Therefore,
			 * mark this type then move onto the RR contents */

            /* First, align the start of the buffer */
            *(unsigned*)(&block->buf[block->offset]) = parser->src.line_number;
            block->offset += 4;
            block->buf[block->offset++] = (unsigned char)(type>>8);
            block->buf[block->offset++] = (unsigned char)(type>>0);
            block->buf[block->offset++] = (unsigned char)(parser->block->ttl>>24);
            block->buf[block->offset++] = (unsigned char)(parser->block->ttl>>16);
            block->buf[block->offset++] = (unsigned char)(parser->block->ttl>> 8);
            block->buf[block->offset++] = (unsigned char)(parser->block->ttl>> 0);
            block->buf[block->offset++] = (unsigned char)(0); /* placeholder for RDLENGTH */
            block->buf[block->offset++] = (unsigned char)(0); /* placeholder for RDLENGTH */

			switch (type) {
			case TYPE_SOA:			s = $RR_SOA;		continue;
			case TYPE_NS:			s = $RR_NS;			mm_domain_start(parser);    continue;
			case TYPE_DNSKEY:		s = $RR_DNSKEY;		continue;
			case TYPE_NSEC:			s = $RR_NSEC;		continue;
			case TYPE_NSEC3:		s = $RR_NSEC3;		continue;
			case TYPE_NSEC3PARAM:	s = $RR_NSEC3PARAM;	continue;
			case TYPE_RRSIG:		s = $RR_RRSIG;		continue;
			case TYPE_DS:			s = $RR_DS;			continue;
			case TYPE_TLSA:			s = $RR_TLSA;		continue;
            case TYPE_SSHFP:        s = $RR_SSHFP;      continue;
			case TYPE_A:			s = $RR_A;			mm_integer_start(parser); continue;
			case TYPE_AAAA:			s = $RR_AAAA;		mm_ipv6_start(parser); continue;
			case TYPE_LOC:			s = $RR_LOC;		mm_location_start(parser); continue;
			case TYPE_TXT:			s = $RR_TXT_START;	continue;
            case TYPE_SRV:          s = $RR_TXT_START;  continue;
            case TYPE_SPF:          s = $RR_TXT_START;  continue;
            case TYPE_HINFO:        s = $RR_TXT_START;  continue;
			case TYPE_MX:			s = $RR_MX;			mm_integer_start(parser); continue;
			case TYPE_PTR:		    s = $RR_PTR;		mm_domain_start(parser); continue;
			case TYPE_CNAME:		s = $RR_CNAME;		mm_domain_start(parser); continue;
                case TYPE_COMMENT:
                    printf(".\n");
                    break;
			default:
				parse_err(parser, "unknown type: %u\n", type);
				s = $PARSE_ERROR;
				continue;
			}
			continue;
		} else if (0x10000 <= type && type <= 0x1FFFF) {
			/* We found a class instead of a type */
			s = $TYPE;
			i--;
			continue;
		} else if (i == length) {
			/* reached end of buffer fragment without completing search,
			 * so loop around and try again */
			continue;
        } else if (type == TYPE_COMMENT) {
            s = $COMMENT;
            /*KLUDGE: we've set the domain-name assuming we were copying
             * the previous domain for an RR. Since ther'es no RR here just
             * a comment, we need to reset this */
            block->offset = block->offset_start;
            continue;        
		} else if (parser->s2 == 0) {
			/* either comment or TTL */
			if (buf[i] == ';') {
				s = $COMMENT;
                continue;
			} else if ('0' <= buf[i] && buf[i] <= '9') {
				parser->block->ttl = buf[i] - '0';
				s = $TTL;
				continue;
			} else {
				parse_err(parser, "unexpected char\n");
				s = $PARSE_ERROR;
				continue;
			}
		} else if ('0' <= buf[i] && buf[i] <= '9') {
			s = $TTL;
			i--;
			parser->s2 = 0;
			continue;
		} else {
			parse_err(parser, "unknown parser: %.10s\n", buf+i-1);
			s = $PARSE_ERROR;
		} 
		continue;
		

	case $PARSE_ERROR:
		i = length;
		continue;

	case $COMMENT:
        /* Should only encounter this on blank-lines with comments. Otherwise,
         * comments should normally be handled within the states for 
         * individual records */
		while (i<length && buf[i] != '\n')
			i++;
		if (i < length)
			s = $LINE_START;
		continue;

	case $TTL:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        parser->block->ttl = parser->rr_number & 0xFFFFFFFF;
		i--;
		s = $TYPE;
		continue;

	case $VARIABLE_TTL:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        parser->block->ttl = parser->rr_number & 0xFFFFFFFF;
		i--;
		s = $UNTIL_EOL;
		continue;

	/*****************/
	case $RR_SOA:
		s = $RR_SOA_DOMAIN;
        mm_domain_start(parser);
	case $RR_SOA_DOMAIN:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_domain_end(parser);
        mm_domain_start(parser);
		s = $RR_SOA_CONTACT;
		parser->s2 = 0;
	case $RR_SOA_CONTACT:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_domain_end(parser);
        mm_integer_start(parser);
		s = $RR_SOA_SERIAL;
	case $RR_SOA_SERIAL:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_SOA_REFRESH;
	case $RR_SOA_REFRESH:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_SOA_RETRY;
	case $RR_SOA_RETRY:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_SOA_EXPIRE;
	case $RR_SOA_EXPIRE:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_SOA_MAX;
	case $RR_SOA_MAX:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
		s = $RR_END;
		goto rr_end;


	/*****************/
	case $RR_NS:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_domain_end(parser);
		s = $RR_END;
		goto rr_end;
	

	/*****************/
	case $RR_CNAME:
    case $RR_PTR:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_domain_end(parser);
		s = $RR_END;
		goto rr_end;


	/*****************/
	case $RR_MX:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_domain_start(parser);
		s = $RR_MX_DOMAIN;
		parser->s2 = 0;
	case $RR_MX_DOMAIN:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
		mm_domain_end(parser);
        s = $RR_END;
		goto rr_end;


	/*****************/
	case $RR_A:
		x_parse_ipv4(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
		s = $RR_END;
		goto rr_end;


	/*****************/
	case $RR_AAAA:
		x_parse_ipv6(parser, buf, &i, length, block->buf + block->offset);
		if (i >= length)
			break;
        mm_ipv6_end(parser);
		s = $RR_END;
		goto rr_end;

	/*****************/
	case $RR_LOC:
		mm_location_parse(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_location_end(parser);
		s = $RR_END;
		goto rr_end;

	/*****************/
	case $RR_TXT_START:
        mm_buffer_start(parser);
        s = $RR_TXT;

	case $RR_TXT:
    txt_again:
		x_parse_txt(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_buffer_end_line(parser);
        if (!isspace(buf[i])) {
            parser->s2 = 0;
            goto txt_again;
        }
        mm_buffer_end(parser);
		s = $RR_END;
		goto rr_end;

    /*
                           1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   algorithm   |    fp type    |                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
       /                                                               /
       /                          fingerprint                          /
       /                                                               /
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    case $RR_SSHFP:
        s = $RR_SSHFP_ALGO;
        mm_integer_start(parser);
	case $RR_SSHFP_ALGO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_integer_start(parser);
		s = $RR_SSHFP_TYPE;
	case $RR_SSHFP_TYPE:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_hex_start(parser);
		s = $RR_SSHFP_FP;
	case $RR_SSHFP_FP:
		x_parse_hex(parser, buf, &i, length, 1);
		if (i >= length)
			break;
        mm_hex_end(parser);
		s = $RR_END;
		goto rr_end;


	/*****************/
    /*
                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |              Flags            |    Protocol   |   Algorithm   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                                                               /
        /                            Public Key                         /
        /                                                               /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
	case $RR_DNSKEY:
		s = $RR_DNSKEY_FLAGS;
		mm_integer_start(parser);
	case $RR_DNSKEY_FLAGS:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
		mm_integer_start(parser);
		s = $RR_DNSKEY_PROTO;
	case $RR_DNSKEY_PROTO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
		mm_integer_start(parser);
		s = $RR_DNSKEY_ALGO;
	case $RR_DNSKEY_ALGO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_base64_start(parser);
		s = $RR_DNSKEY_KEY;
	case $RR_DNSKEY_KEY:
		x_parse_base64(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_base64_end(parser);
		s = $RR_END;
		goto rr_end;

	/*
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Cert. Usage  |   Selector    | Matching Type |               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
   /                                                               /
   /                 Certificate Association Data                  /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
	case $RR_TLSA:
		s = $RR_TLSA_USAGE;
		mm_integer_start(parser);
	case $RR_TLSA_USAGE:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_integer_start(parser);
		s = $RR_TLSA_SELECTOR;
	case $RR_TLSA_SELECTOR:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_integer_start(parser);
		s = $RR_TLSA_TYPE;
	case $RR_TLSA_TYPE:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_hex_start(parser);
		s = $RR_TLSA_CERT;
	case $RR_TLSA_CERT:
		x_parse_hex(parser, buf, &i, length, 1);
		if (i >= length)
			break;
        mm_hex_end(parser);
		s = $RR_END;
		goto rr_end;

	/*****************
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Type Covered           |  Algorithm    |     Labels    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Original TTL                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Signature Expiration                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Signature Inception                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Key Tag            |                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                            Signature                          /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
	case $RR_RRSIG:
		mm_integer_start(parser);
		s = $RR_RRSIG_TYPE;
	case $RR_RRSIG_TYPE:
		parser->rr_number = mydfa_search(parser->type_dfa, &parser->s2, buf, &i, length);
		if (i >= length)
			continue;
        mm_integer16_end(parser);
        mm_integer_start(parser);
		s = $RR_RRSIG_ALGO;		
	case $RR_RRSIG_ALGO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_integer_start(parser);
		s = $RR_RRSIG_LABEL;
	case $RR_RRSIG_LABEL:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_integer_start(parser);
		s = $RR_RRSIG_TTL;
	case $RR_RRSIG_TTL:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_RRSIG_EXPIRE;
	case $RR_RRSIG_EXPIRE:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
		parser->rr_number = rrsig_expiration_translate(parser->rr_number);
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_RRSIG_INCEPT;
	case $RR_RRSIG_INCEPT:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
		parser->rr_number = rrsig_expiration_translate(parser->rr_number);
        mm_integer32_end(parser);
        mm_integer_start(parser);
		s = $RR_RRSIG_TAG;
	case $RR_RRSIG_TAG:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer16_end(parser);
        mm_domain_start(parser);
		s = $RR_RRSIG_NAME;
	case $RR_RRSIG_NAME:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_domain_end(parser);
        mm_base64_start(parser);
		s = $RR_RRSIG_SIGNATURE;
	case $RR_RRSIG_SIGNATURE:
		x_parse_base64(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_base64_end(parser);
		s = $RR_END;
		goto rr_end;

    /* http://tools.ietf.org/html/rfc5155#section-4.1

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Hash Alg.   |     Flags     |          Iterations           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Salt Length  |                     Salt                      /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
	case $RR_NSEC3PARAM:
        mm_integer_start(parser);
		s = $RR_NSEC3PARAM_ALGO;
	case $RR_NSEC3PARAM_ALGO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_integer_start(parser);
		s = $RR_NSEC3PARAM_FLAGS;
	case $RR_NSEC3PARAM_FLAGS:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_integer_start(parser);
		s = $RR_NSEC3PARAM_ITERATIONS;
	case $RR_NSEC3PARAM_ITERATIONS:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_hex_start(parser);
		s = $RR_NSEC3PARAM_SALT1;
	case $RR_NSEC3PARAM_SALT1:
		s = $RR_NSEC3PARAM_SALT2;
	case $RR_NSEC3PARAM_SALT2:
		x_parse_hex(parser, buf, &i, length, 1);
		if (i >= length)
			break;
        mm_hex_end(parser);
		s = $RR_END;
		goto rr_end;

    /* RFC 4034 5.1 */
    /*

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Key Tag             |  Algorithm    |  Digest Type  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                                                               /
        /                            Digest                             /
        /                                                               /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */	
    case $RR_DS:
		mm_integer_start(parser);
		s = $RR_DS_TAG;
	case $RR_DS_TAG:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer16_end(parser);
		mm_integer_start(parser);
		s = $RR_DS_ALGO;
	case $RR_DS_ALGO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_integer_start(parser);
		s = $RR_DS_TYPE;
	case $RR_DS_TYPE:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
		mm_hex_start(parser);
		s = $RR_DS_DIGEST;
	case $RR_DS_DIGEST:
		x_parse_hex(parser, buf, &i, length, 1);
		if (i >= length)
			break;
        mm_hex_end(parser);
		s = $RR_END;
		goto rr_end;


    /*

                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                      Next Domain Name                         /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                       Type Bit Maps                           /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
	case $RR_NSEC:
        mm_domain_start(parser);
		s = $RR_NSEC_DOMAIN;
	case $RR_NSEC_DOMAIN:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_domain_end(parser);
        mm_typelist_start(parser);
		s = $RR_NSEC3_FLAGS;
	case $RR_NSEC_TYPES:
		while (i < length) {
			type = x_parse_type(parser, buf, &i, length);
			if (type == 0)
				break;
			parser->s2 = 0;
			if (type == 0xFFFFFFFF)
				break;
			if (0 < type && type < 0x10000) {
                if (parser->rr_typelist.count < 64)
                    parser->rr_typelist.list[parser->rr_typelist.count++] = (unsigned short)type;
				continue;
			} 
		}
		if (i >= length)
			break;
        mm_typelist_end(parser);
		s = $RR_END;
		goto rr_end;

	/*****************/
    /* http://tools.ietf.org/html/rfc5155#section-3.2
                            1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Hash Alg.   |     Flags     |          Iterations           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Salt Length  |                     Salt                      /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Hash Length  |             Next Hashed Owner Name            /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                         Type Bit Maps                         /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
	case $RR_NSEC3:
        mm_integer_start(parser);
		s = $RR_NSEC3_ALGO;
	case $RR_NSEC3_ALGO:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_integer_start(parser);
		s = $RR_NSEC3_FLAGS;
	case $RR_NSEC3_FLAGS:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
        mm_integer8_end(parser);
        mm_integer_start(parser);
		s = $RR_NSEC3_ITERATIONS;
	case $RR_NSEC3_ITERATIONS:
		x_parse_ttl(parser, buf, &i, length);
		if (i >= length)
			break;
		mm_integer16_end(parser);
        mm_hex_start(parser);
        s = $RR_NSEC3_SALT;
	case $RR_NSEC3_SALT:
		x_parse_hex(parser, buf, &i, length, 0);
		if (i >= length)
			break;
    	mm_hex_end(parser);
        mm_base32_start(parser);
		s = $RR_NSEC3_HASH;
	case $RR_NSEC3_HASH:
		x_parse_base32hex(parser, buf, &i, length);
		if (i >= length)
			break;
    	mm_base32_end(parser);
        mm_typelist_start(parser);
		s = $RR_NSEC3_TYPES;
	case $RR_NSEC3_TYPES:
		while (i < length) {
			type = x_parse_type(parser, buf, &i, length);
			if (type == 0)
				break;
			if (type == 0xFFFFFFFF)
				break;
			parser->s2 = 0;
			if (0 < type && type < 0x10000) {
                if (parser->rr_typelist.count < 64)
                    parser->rr_typelist.list[parser->rr_typelist.count++] = (unsigned short)type;
				continue;
			} 
		}
		if (i >= length)
			break;
        mm_typelist_end(parser);
		s = $RR_END;
		goto rr_end;

		

	case $VARIABLE:
		{
			unsigned variable;

			variable = mydfa_search(parser->variable_dfa, &parser->s2, buf, &i, length);
			switch (variable) {
			case 1: /* $ORIGIN */
				i--;
				s = $ORIGIN;
                mm_domain_start(parser);
                parser->rr_domain.name = block->origin_buffer;
				parser->s2 = 0;
				continue;
			case 2: /* $TTL */
				i--;
				s = $VARIABLE_TTL;
				parser->s2 = 0;
				continue;

			case 3: /* $INCLUDE */
				i--;
				s = $PARSE_ERROR;
				parser->s2 = 0;
				parse_err(parser, "unsupported feature\n");
				continue;
			default:
				parse_err(parser, "unxpected\n");
				s = $PARSE_ERROR;
				continue;
			case 0:
				if (i == length) {
					/* fragment */
					continue;
				} else {
					parse_err(parser, "unxpected\n");
					s = $PARSE_ERROR;
					continue;
				}
			}
		} 
		continue;

	case $ORIGIN:
		x_parse_domain(parser, buf, &i, length);
		if (i >= length)
			break;

        /* [1] We need to make sure this is an 'absolute' domain name
         * rather than relative to the previous origin. */
        if (!parser->rr_domain.is_absolute) {
			parse_err(parser, "$ORIGIN must be fully qualified domain name (end in '.')\n");
			s = $PARSE_ERROR;
			continue;
        }

        //mm_domain_end(parser);

        /* We need to update both the 'parser' and the current 'block' with
         * the new origin info */
        parser->block->origin.length = parser->rr_domain.label;
        parser->block->origin.name = parser->block->origin_buffer;
        
		i--;
		s = $UNTIL_EOL;
		continue;

	default:
		if (s == '\n') {
            parser->src.line_number++;
			s = $LINE_START;
			continue;
		}
		break;
	}
	}

	parser->s = s;
}

/****************************************************************************
 ****************************************************************************/

/****************************************************************************
 * Called to parse a chunk of a zone-file.
 * @param parser
 *      A parser object created with a call to zonefile_start(), which will
 *      later be destroy by a call to zonefile_end(). This is a temporary
 *      parser object only used during the parse, destroy it doesn't
 *      destroy any data. This is reentrent, so many parsers can be created.
 * @param filename
 *      A helpful filename for printing error messages. Note that the parser
 *      doesn't know where input comes from, so it doesn't have to be from
 *      a file. One possibility is that messages are transfered over 
 *      some other protocol like FTP and fed directly to the parser.
 * @param callback
 *      The parser will call this once for every resource-record (RR), as
 *      well as pseudo-resource records like $INCLUDE. The caller will
 *      presumably copy the indicated resource record into a database.
 * @param userdata
 *      Opaque data that will be passed through to the callback. Presumably
 *      this is the database that the resource-records are going to be 
 *      copied into.
 * @param buf
 *      A block of data read from a zone-file. The parser reassembles lines,
 *      so the caller doesn't have to worry about line boundaries (and
 *      indeed, trying to align blocks on line boundaries, such as using
 *      fgets(), would be a very bad thing. Better to fread(.., 65536, ...)
 *      to read large chunks at a time.
 * @param buf_length
 *      The legth of a block, from [1..UINT_MAX] in size.
 ****************************************************************************/
void
zonefile_parse(
    struct ZoneFileParser *parser,
    const unsigned char *buf,
    size_t buf_length)
{
    x_parse(    
        parser, 
        buf, 
        (unsigned)buf_length
	    );
}

/******************************************************************************
 ******************************************************************************/
void
zonefile_set_singlestep(struct ZoneFileParser *parser)
{
    parser->is_singlestep = 1;
}

/******************************************************************************
 * Call this to create a parser for parsing a file.
 * @return an object suitable for parsing
 ******************************************************************************/
struct ZoneFileParser *
zonefile_begin(struct DomainPointer origin, uint64_t ttl, uint64_t filesize,
    const char *filename, RESOURCE_RECORD_CALLBACK callback, void *callbackdata,
    unsigned extra_threads)
{
    struct ZoneFileParser *parser;

    parser = MALLOC2(sizeof(parser[0]));
    memset(parser, 0, sizeof(parser[0]));

    /* remember filesize as a hint when creating the zone hash table */
    parser->filesize = filesize;
    parser->callback = callback;
    parser->callbackdata = callbackdata;
    parser->src.filename = filename;

    parser->type_dfa = _type_dfa;
	parser->variable_dfa = _variable_dfa;

    /*
     * Initialize the "block-insertion" system
     */
    parser->additional_threads = extra_threads;
    parser->block = block_init(parser, origin, ttl);

    return parser;
}

/******************************************************************************
 * Call this to re-use the parser to parse multiple files
 ******************************************************************************/
void
zonefile_begin_again(
    struct ZoneFileParser *parser,
    struct DomainPointer origin, uint64_t ttl, uint64_t filesize,
    const char *filename)
{
    struct ParsedBlock *block;

    /* remember filesize as a hint when creating the zone hash table */
    parser->filesize = filesize;
    parser->src.filename = filename;

    /* move to a new block */
    block = block_next_to_parse(parser);
    if (block->filesize != filesize) {
        memcpy(block->filename, parser->src.filename, sizeof(block->filename));
        block->filesize = parser->filesize;
    }


    block->ttl = ttl;
    block->origin.name = origin.name;
    block->origin.length = origin.length;
}

/****************************************************************************
 ****************************************************************************/
int
zonefile_end(struct ZoneFileParser *parser)
{
    int result;
    

    /*
     * Wait for all threads to finish inserting data
     */
    zonefile_flush(parser);

    /*
     * Cleanup the block-insertiong stuff
     */
    block_end(parser);

    if (parser->src.error_count)
        result = Failure;
    else
        result = Success;
    free(parser);
    return result;
}


/****************************************************************************
 * Call this from main() at process startup to initialize some data
 * strutures used in parsing.
 ****************************************************************************/
int
zonefile_parser_init(void)
{
    static int once_only = 0;
    if (once_only)
        return Failure;
    else
        once_only = 1;

	isdomainchar_init();
	build_type_dfa(_type_dfa);
	build_variable_dfa(_variable_dfa);
    return Success;
}

/****************************************************************************
 * Called during <selftest> to flush outstanding data and save into the
 * catalog.
 ****************************************************************************/
int zonefile_flush(struct ZoneFileParser *parser)
{
    /* First, terminate processing of the current block */
    block_next_to_parse(parser);

    /* Second, wait for all blocks to be processed */
    block_flush(parser);

    return Success;
}