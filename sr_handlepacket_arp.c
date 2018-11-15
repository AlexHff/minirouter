#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_handlepacket_arp.h"

void sr_handlepacket_arp(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
    sr_ethernet_hdr_t *hdr_eth = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t *hdr_arp = (sr_arp_hdr_t*) packet;
    print_hdr_ip(packet);
    print_hdr_eth(hdr_eth);
    print_hdr_arp(hdr_arp);
}
