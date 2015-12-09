#include "main-conf.h"
#include "configuration.h"
#include "logger.h"
#include "pixie-threads.h"
#include "pixie-sockets.h"
#include "pixie-timer.h"
#include "string_s.h"
#include "proto-dns.h"
#include "proto-dns-compressor.h"
#include "proto-dns-formatter.h"
#include "resolver.h"
#include "util-realloc2.h"

/****************************************************************************
 ****************************************************************************/
static void
thread_worker(void *p)
{
    struct CoreWorkerThread *t = (struct CoreWorkerThread *)p;
    struct Core *core = t->core;

    while (!t->should_end) {
        unsigned i;
        struct CoreSocketSet *sockets;
        fd_set readfds;
        int nfds = 0;
        int x;
        struct timeval ts;

        /* [SYNCHRONIZATION POINT] 
        * mark the fact we are using the new socket-set */
        sockets = (struct CoreSocketSet *)core->socket_run;
        t->loop_count++;

        /* During startup, the sockets argument may be NULL for a time.
         * if that's the case, then just wait for a little bit, and try
         * again */
        if (sockets == NULL) {
            /* Sleep for a 10th of a second */
            pixie_mssleep(10); 
            continue;
        }

        /* 
         * See if there are any packets waiting 
         */
        FD_ZERO(&readfds);
        for (i=0; i<sockets->count; i++) {
            FD_SET(sockets->list[i].fd, &readfds);
            if (nfds < sockets->list[i].fd)
                nfds = sockets->list[i].fd;
        }
        ts.tv_sec = 0;
        ts.tv_usec = 1000; /* one millisecond */

        x = select(nfds, &readfds, 0, 0, &ts);
        if (x < 0) {
            LOG_ERR(C_NETWORK, "select() returned error %u\n", WSAGetLastError());
            pixie_mssleep(1000);
            /* at this point, the errors are probably unrecoverable
             * until the system is manually reconfigured */
            continue;
        }
        if (x == 0)
            continue; /* nothing found */

        /*
         * Process any packets that have arrived
         */
        for (i=0; i<sockets->count; i++) {
            struct sockaddr_storage sin;
            socklen_t sizeof_sin = sizeof(sin);
            unsigned char buf[2048];
            unsigned char buf2[2048];
            int bytes_received;
            struct DNS_Incoming request[1];
            struct DNS_OutgoingResponse response[1];
            struct Packet pkt;
            int fd;

            fd = sockets->list[i].fd;
            if (!FD_ISSET(fd, &readfds))
                continue;
        
            /*
             * 1. receive 'packet'
             */
            bytes_received = recvfrom(fd, 
                                      (char*)buf, sizeof(buf),
                                      0, 
                                      (struct sockaddr*)&sin, &sizeof_sin);
            if (bytes_received == 0)
                continue;

        
            /*
             * 2. parse 'packet' into a 'request'
             */
            proto_dns_parse(request, buf, 0, bytes_received);
            if (!request->is_valid)
                continue;


            /*
             * 3. resolve 'request' into a 'repsonse'
             */
            resolver_init(response, 
                          request->query_name.name, 
                          request->query_name.length, 
                          request->query_type,
                          request->id,
                          request->opcode);
            
            resolver_algorithm(core->db_run, response, request);
            

            /*
             * 4. format the 'response' into a 'packet'
             */
            pkt.buf = buf2;
            pkt.max = sizeof(buf2);
            pkt.offset = 0;
            dns_format_response(response, &pkt);
            
            /*
             * 5. Transmit the 'packet'
             */
            if (pkt.offset < pkt.max) {
                sendto(fd, 
                       (char*)pkt.buf, pkt.offset, 0,
                       (struct sockaddr*)&sin,
                       sizeof_sin);
            }
        }
    }
}

/****************************************************************************
 ****************************************************************************/
static void
thread_worker_start(struct Core *core)
{
    struct CoreWorkerThread *t;

    t = malloc(sizeof(*t));
    if (t == 0)
        return;
    memset(t, 0, sizeof(*t));

    t->core = core;
    t->index = core->workers_count;

    t->handle = pixie_begin_thread(thread_worker, 0, t);
    if (t->handle == 0) {
        LOG_ERR(C_GENERAL, "can't start worker thread %u\n", errno);
        free(t);
        return;
    }

    /*
     * Append to our list of worker threads
     */
    core->workers = REALLOC2(core->workers, core->workers_count + 1, sizeof(core->workers[0]));
    core->workers[core->workers_count] = t;
    core->workers_count++;
}

/****************************************************************************
 ****************************************************************************/
static void
thread_worker_stop(struct Core *core)
{
    struct CoreWorkerThread *t;
    size_t x = 0;

    /*
     * Remove a random worker thread from the list
     */
    core->workers_count--;
    t = core->workers[core->workers_count];
    
    /* Wait until the thread ends */
    t->should_end = 1;
    pixie_join(t->handle, &x);
    
    /* Destroy the thread object */
    free(t);
}

/****************************************************************************
 ****************************************************************************/
void
change_resolver_threads(struct Core *core, struct Configuration *cfg_new)
{
    /* If no threads were specified, then default to the number of threads
     * in the system */
    if (cfg_new->worker_threads == 0) {
        cfg_new->worker_threads = pixie_cpu_get_count();
    }
    if (cfg_new->worker_threads == 0)
        cfg_new->worker_threads = 1;
    if (cfg_new->worker_threads > 1024)
        cfg_new->worker_threads = 1024;

    /* See if we need to stop some threads */
    while (core->workers_count > cfg_new->worker_threads) {
        thread_worker_stop(core);
    }

    /* See if we need to start some threads */
    while (core->workers_count < cfg_new->worker_threads) {

        thread_worker_start(core);
    }
}


/****************************************************************************
 ****************************************************************************/


