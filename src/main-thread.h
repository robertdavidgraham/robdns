#ifndef MAIN_THREAD_H
#define MAIN_THREAD_H

void main_thread(void *parms);

struct ThreadParms
{
    unsigned nic_index;
    unsigned adapter_ip;
    unsigned char adapter_mac[6];
    struct Adapter *adapter;

    struct Catalog *catalog_run;
};

#endif
