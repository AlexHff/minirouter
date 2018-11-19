#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_handlepacket_arp.h"

void sr_handlepacket_ip(struct sr_instance* sr,
                         uint8_t * packet,
                         unsigned int len)
{
    /* Verify IP packet is of correct length*/
    int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if (len < minlength) {
        fprintf(stderr, "Failed to handle ip packet, insufficient length\n");
        return;
    }
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t sum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    if (sum == cksum(iphdr, sizeof(sr_ip_hdr_t))) {
        fprintf(stderr, "Failed to handle ip packet, checksum does not match\n");
        return;
    }
}