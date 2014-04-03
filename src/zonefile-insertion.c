#include "zonefile-insertion.h"
#include "zonefile-fields.h"
#include "rte-ring.h"
#include "pixie-timer.h"
#include "pixie-threads.h"
#include <string.h>

/****************************************************************************
 ****************************************************************************/
static void
insert_block_into_catalog(struct ParsedBlock *block, RESOURCE_RECORD_CALLBACK callback, void *userdata, uint64_t filesize)
{
    unsigned i;
    unsigned max = block->offset;

    for (i=0; i<max; ) {
        const unsigned char *buf = block->buf;
        struct DomainPointer domain;
        const unsigned char *rdata;
        unsigned type;
        unsigned ttl;
        unsigned rdlength;

        domain.length = buf[i];
        domain.name = &buf[i+1];

        i += domain.length + 1;

        type = buf[i+0]<<8 | buf[i+1];
        ttl = buf[i+2]<<24 | buf[i+3]<<16 | buf[i+4]<<8 | buf[i+5];
        rdlength = buf[i+6]<<8 | buf[i+7];
        i += 8;

        rdata = &buf[i];
        i += rdlength;


        callback(
            domain,
            block->origin,
            type,
            ttl,
            rdlength,
            rdata,
            filesize,
            userdata);
    }

    block->offset = 0;
    block->offset_start = 0;
}



/****************************************************************************
 * BLOCKS: By grouping multiple RRs together in a "block", we can have
 * multiple threads updating the zone database without having to interact
 * much with each other.
 ****************************************************************************/
struct ParsedBlock *
block_next_to_parse(struct ZoneFileParser *parser)
{
    struct DomainPointer origin;
    unsigned char origin_buffer[256];
	uint64_t ttl;
    struct ParsedBlock *block = parser->block;
    int err;

    /*
     * Copy the state from the existing block
     */
    memcpy(origin_buffer, block->origin_buffer, 256);
    origin.name = origin_buffer;
    origin.length = block->origin.length;
    ttl = block->ttl;

    /*
     * Insert this block into the processing queue
     */
    rte_ring_enqueue(parser->insertion_queue, block);

    /*
     * Get a new block from the free queue
     */
    for (err=1; err; ) {
        err = rte_ring_dequeue(parser->free_queue, (void**)&block);
        if (err != 0) {
            static int is_warning_printed = 0;
            if (!is_warning_printed) {
                fprintf(stderr, "insertion slow, parser waiting\n");
                is_warning_printed = 1;
            }
            fflush(stdout);
            pixie_usleep(100);
        }
    }
    parser->block = block;

    /*
     * Copy state from previous block
     */
    memcpy(block->origin_buffer, origin_buffer, 256);
    block->origin.name = block->origin_buffer;
    block->origin.length = origin.length;
    block->ttl = ttl;

    parser->block = block;

    /*
     * If we are single threaded, then pull the block off the
     * queue and process it
     */
    if (parser->additional_threads == 0) {
        for (err=1; err; ) {
            err = rte_ring_dequeue(parser->insertion_queue, (void**)&block);
            if (err != 0) {
                static int is_warning_printed = 0;
                if (!is_warning_printed) {
                    fprintf(stderr, "de-insertion slow, parser waiting\n");
                    is_warning_printed = 1;
                }
                fflush(stdout);
                pixie_usleep(100);
            }
        }
        insert_block_into_catalog(block, parser->callback, parser->callbackdata, parser->filesize);
        //printf("." "MAIN-THREAD: inserted block\n");
        rte_ring_enqueue(parser->free_queue, block);
    }

    return parser->block;
}



/****************************************************************************
 ****************************************************************************/
static void
insertion_thread(void *v)
{
    struct ZoneFileParser *parser = (struct ZoneFileParser *)v;

    pixie_locked_add_u32(&parser->running_threads, 1);

    /* 
     * just sit in a loop grabbing work units as they arrive 
     */
    while (parser->is_running) {
        struct ParsedBlock *block;
        int err;

        for (err=1; err && parser->is_running; ) {
            err = rte_ring_dequeue(parser->insertion_queue, (void**)&block);
            if (err != 0) {
                static int is_warning_printed = 0;
                if (!is_warning_printed) {
                    fprintf(stderr, "de-insertion slow, parser waiting\n");
                    is_warning_printed = 1;
                }
                fflush(stdout);
                pixie_usleep(100);
            }
        }
        insert_block_into_catalog(block, parser->callback, parser->callbackdata, parser->filesize);
        //printf("." "INSERTION-THREAD: inserted block\n");
        rte_ring_enqueue(parser->free_queue, block);

    }

    pixie_locked_add_u32(&parser->running_threads, -1);

    printf("parser->running threads = %u\n", parser->running_threads);
}

/****************************************************************************
 ****************************************************************************/
struct ParsedBlock *
block_init(struct ZoneFileParser *parser, 
            struct DomainPointer origin,
            uint64_t ttl)
{
    unsigned i;

    /* Create a buffer of parse-blocks */
    parser->insertion_queue = rte_ring_create(128, 0);
    parser->free_queue = rte_ring_create(128, 0);
    for (i=0; i<sizeof(parser->the_blocks)/sizeof(parser->the_blocks[0]); i++) {
        rte_ring_enqueue(parser->free_queue, &parser->the_blocks[i]);
    }

    /* initialize the first parse block */
    rte_ring_dequeue(parser->free_queue, (void**)&parser->block);
    if (origin.length) {
        parser->block->origin.length = (unsigned char)origin.length;
        parser->block->origin.name = parser->block->origin_buffer;
        memcpy(parser->block->origin_buffer, origin.name, parser->block->origin.length);
    }
    if (ttl) {
        parser->block->ttl = ttl;
    }

    /*
     * Start the insertion threads
     */
    parser->is_running = 1;
    for (i=0; i<parser->additional_threads; i++) {
        pixie_begin_thread(insertion_thread, 0, parser);
    }

    return parser->block;
}

/****************************************************************************
 ****************************************************************************/
void
block_end(struct ZoneFileParser *parser)
{
    parser->is_running = 0;
    while (parser->running_threads) {
        pixie_usleep(1000);
    }
}

/****************************************************************************
 ****************************************************************************/
void
block_flush(struct ZoneFileParser *parser)
{
    while (rte_ring_count(parser->free_queue) != 63) {
        pixie_usleep(100);
    }
}


