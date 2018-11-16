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
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t *ahdr = (sr_arp_hdr_t*) packet;

    switch(arptype(ahdr))
    {
        case arp_op_request:
            printf("      Received ARP request.");
            sr_handlepacket_arp_request(sr, packet, len, interface, ehdr, ahdr);
            break;
        case arp_op_reply:
            printf("      Received ARP reply.");
            /*sr_handlepacket_arp_reply();*/
            break;
        default:
            fprintf(stderr, "      Error in ARP type, dropping packet.\n");
    }
}

void sr_handlepacket_arp_request(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */,
                     sr_ethernet_hdr_t *ehdr,
                     sr_arp_hdr_t *ahdr)
{

}
