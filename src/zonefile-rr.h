#ifndef ZONE_RR_H
#define ZONE_RR_H
#include <stdint.h>
#include <stdio.h>

enum {
TYPE_A			= 1, //RFC 1035[1]	address record	Returns a 32-bit IPv4 address, most commonly used to map hostnames to an IP address of the host, but also used for DNSBLs, storing subnet masks in RFC 1101, etc.
TYPE_AAAA		= 28, //RFC 3596[2]	IPv6 address record	Returns a 128-bit IPv6 address, most commonly used to map hostnames to an IP address of the host.
TYPE_AFSDB		= 18, //RFC 1183	AFS database record	Location of database servers of an AFS cell. This record is commonly used by AFS clients to contact AFS cells outside their local domain. A subtype of this record is used by the obsolete DCE/DFS file system.
TYPE_APL		= 42, //RFC 3123	Address Prefix List	Specify lists of address ranges, e.g. in CIDR format, for various address families. Experimental.
TYPE_CAA		= 257, //RFC 6844	Certification Authority Authorization	CA pinning, constraining acceptable CAs for a host/domain
TYPE_CERT		= 37, //RFC 4398	Certificate record	Stores PKIX, SPKI, PGP, etc.
TYPE_CNAME		= 5, //RFC 1035[1]	Canonical name record	Alias of one name to another: the DNS lookup will continue by retrying the lookup with the new name.
TYPE_DHCID		= 49, //RFC 4701	DHCP identifier	Used in conjunction with the FQDN option to DHCP
TYPE_DLV		= 32769, //RFC 4431	DNSSEC Lookaside Validation record	For publishing DNSSEC trust anchors outside of the DNS delegation chain. Uses the same format as the DS record. RFC 5074 describes a way of using these records.
TYPE_DNAME		= 39, //RFC 2672	delegation name	DNAME creates an alias for a name and all its subnames, unlike CNAME, which aliases only the exact name in its label. Like the CNAME record, the DNS lookup will continue by retrying the lookup with the new name.
TYPE_DNSKEY		= 48, //RFC 4034	DNS Key record	The key record used in DNSSEC. Uses the same format as the KEY record.
TYPE_DS			= 43, //RFC 4034	Delegation signer	The record used to identify the DNSSEC signing key of a delegated zone
TYPE_HIP		= 55, //RFC 5205	Host Identity Protocol	Method of separating the end-point identifier and locator roles of IP addresses.
TYPE_HINFO      = 13, //RFC 1035    Host Information
TYPE_IPSECKEY	= 45, //RFC 4025	IPsec Key	Key record that can be used with IPsec
TYPE_KEY		= 25, //RFC 2535[3] and RFC 2930[4]	key record	Used only for SIG(0) (RFC 2931) and TKEY (RFC 2930).[5] RFC 3445 eliminated their use for application keys and limited their use to DNSSEC.[6] RFC 3755 designates DNSKEY as the replacement within DNSSEC.[7] RFC 4025 designates IPSECKEY as the replacement for use with IPsec.[8]
TYPE_KX			= 36, //RFC 2230	Key eXchanger record	Used with some cryptographic systems (not including DNSSEC) to identify a key management agent for the associated domain-name. Note that this has nothing to do with DNS Security. It is Informational status, rather than being on the IETF standards-track. It has always had limited deployment, but is still in use.
TYPE_LOC		= 29, //RFC 1876	Location record	Specifies a geographical location associated with a domain name
TYPE_MX			= 15, //RFC 1035[1]	mail exchange record	Maps a domain name to a list of message transfer agents for that domain
TYPE_NAPTR		= 35, //RFC 3403	Naming Authority Pointer	Allows regular expression based rewriting of domain names which can then be used as URIs, further domain names to lookups, etc.
TYPE_NS			= 2, //RFC 1035[1]	name server record	Delegates a DNS zone to use the given authoritative name servers
TYPE_NSEC		= 47, //RFC 4034	Next-Secure record	Part of DNSSEC—used to prove a name does not exist. Uses the same format as the (obsolete) NXT record.
TYPE_NSEC3		= 50, //RFC 5155	NSEC record version 3	An extension to DNSSEC that allows proof of nonexistence for a name without permitting zonewalking
TYPE_NSEC3PARAM	= 51, //RFC 5155	NSEC3 parameters	Parameter record for use with NSEC3
TYPE_PTR		= 12, //RFC 1035[1]	pointer record	Pointer to a canonical name. Unlike a CNAME, DNS processing does NOT proceed, just the name is returned. The most common use is for implementing reverse DNS lookups, but other uses include such things as DNS-SD.
TYPE_RRSIG		= 46, //RFC 4034	DNSSEC signature	Signature for a DNSSEC-secured record set. Uses the same format as the SIG record.
TYPE_RP			= 17, //RFC 1183	Responsible person	Information about the responsible person(s) for the domain. Usually an email address with the @ replaced by a .
TYPE_SIG		= 24, //RFC 2535	Signature	Signature record used in SIG(0) (RFC 2931) and TKEY (RFC 2930).[7] RFC 3755 designated RRSIG as the replacement for SIG for use within DNSSEC.[7]
TYPE_SOA		= 6, //RFC 1035[1]	start of [a zone of] authority record	Specifies authoritative information about a DNS zone, including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone.
TYPE_SPF		= 99, //RFC 4408	Sender Policy Framework	Specified as part of the SPF protocol as an alternative to of storing SPF data in TXT records. Uses the same format as the earlier TXT record.
TYPE_SRV		= 33, //RFC 2782	Service locator	Generalized service location record, used for newer protocols instead of creating protocol-specific records such as MX.
TYPE_SSHFP		= 44, //RFC 4255	SSH Public Key Fingerprint	Resource record for publishing SSH public host key fingerprints in the DNS System, in order to aid in verifying the authenticity of the host. RFC 6594 defines ECC SSH keys and SHA-256 hashes. See the IANA SSHFP RR parameters registry for details.
TYPE_TA			= 32768, //N/A	DNSSEC Trust Authorities	Part of a deployment proposal for DNSSEC without a signed DNS root. See the IANA database and Weiler Spec for details. Uses the same format as the DS record.
TYPE_TKEY		= 249, //RFC 2930	secret key record	A method of providing keying material to be used with TSIG that is encrypted under the public key in an accompanying KEY RR.[9]
TYPE_TLSA		= 52, //RFC 6698	TLSA certificate association	A record for DNS-based Authentication of Named Entities (DANE). RFC 6698 defines "The TLSA DNS resource record is used to associate a TLS server certificate or public key with the domain name where the record is found, thus forming a 'TLSA certificate association'".
TYPE_TSIG		= 250, //RFC 2845	Transaction Signature	Can be used to authenticate dynamic updates as coming from an approved client, or to authenticate responses as coming from an approved recursive name server[10] similar to DNSSEC.
TYPE_TXT		= 16, //RFC 1035[1]	Text record	Originally for arbitrary human-readable text in a DNS record. Since the early 1990s, however, this record more often carries machine-readable data, such as specified by RFC 1464, opportunistic encryption, Sender Policy Framework, DKIM, DMARC DNS-SD, etc.
TYPE_ANY		= 255, //RFC 1035[1]	Text record	Originally for arbitrary human-readable text in a DNS record. Since the early 1990s, however, this record more often carries machine-readable data, such as specified by RFC 1464, opportunistic encryption, Sender Policy Framework, DKIM, DMARC DNS-SD, etc.


TYPE_PERENS_OPEN     = 0x40000,
TYPE_PERENS_CLOSE    = 0x40001,
TYPE_COMMENT         = 0x40002,
};







#endif
