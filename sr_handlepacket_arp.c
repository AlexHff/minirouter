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
    /* verify that ARP is of correct length*/
    if (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t) > len)
    {
        fprintf(stderr, "      Error in ARP length, dropping packet.\n");
        return;
    }
    else
    {
        sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;
        sr_arp_hdr_t *ahdr = (sr_arp_hdr_t*) packet;

        uint16_t atype = 0;

        if(arptype(ahdr) == 6665)
            atype = 1;
        else if (arptype(ahdr) == 6666)
            atype = 2;

        switch(atype)
        {
        case arp_op_request:
            printf("request\n");
            sr_handlepacket_arp_request(sr, packet, len, interface, ehdr, ahdr);
            break;
        case arp_op_reply:
            printf("reply\n");
            /*sr_handlepacket_arp_reply();*/
            break;
        default:
            fprintf(stderr, "      Error in ARP type, dropping packet.\n");
            return;
        }
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
