#ifndef PROTO_DNS_COMPRESSOR_H
#define PROTO_DNS_COMPRESSOR_H
struct DNS_OutgoingResponse;
struct Packet;
struct DomainPointer;

/****************************************************************************
 ****************************************************************************/
struct CompressorId {
    const unsigned char *label;
    unsigned short sibling;
    unsigned short child;
    unsigned short compression_code;
};
struct Compressor
{
    unsigned offset_start;
    unsigned count;
    struct CompressorId ids[1000];
};

void compressor_init(struct Compressor *compressor, const struct DNS_OutgoingResponse *response, unsigned offset_start);
void compressor_append_name(struct Compressor *compressor, struct Packet *pkt, struct DomainPointer name, struct DomainPointer origin);
int compressor_selftest(const struct DNS_OutgoingResponse *response);

#endif
