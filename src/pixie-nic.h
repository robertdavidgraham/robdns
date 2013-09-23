#ifndef PIXIE_NIC_H
#define PIXIE_NIC_H
#include <stdio.h>

/**
 * Tests to see if the named network adapter exists
 *
 * @param ifname
 *      The name of a network interface
 * @return
 *      1 if the named network interface exists
 *      0 if it doesn't exists or is somehow invalid
 */
unsigned pixie_nic_exists(const char *ifname);

unsigned pixie_nic_get_default(char *ifname, size_t ifname_size);

unsigned pixie_nic_get_ipv4(const char *ifname);

unsigned pixie_nic_get_mac(const char *ifname, unsigned char *mac);

unsigned pixie_nic_gateway(const char *ifname, unsigned *ipv4);


#endif
