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
    /* Verify ARP is of correct length*/
    if(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t) > len)
    {
        fprintf(stderr, "Error in ARP length, dropping packet.\n");
        return;
    }
    else
    {
        /* Get interface the packet is for */
        struct sr_if *recv_interface = sr_get_interface(sr, interface);

        /* Extract hdr from packet */
        sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;
        sr_arp_hdr_t *ahdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        /* Cache every ARP we get */
        sr_arpcache_insert(&sr->cache, ahdr->ar_sha, ahdr->ar_sip);

        print_hdr_arp(packet);

        /* Find ARP type to proceed appropriately */
        switch(arptype(ahdr))
        {
        case arp_op_request:
            printf("request\n");
            sr_handlepacket_arp_request(sr, packet, len, recv_interface, ehdr, ahdr);
            break;
        case arp_op_reply:
            printf("reply\n");
            /*sr_handlepacket_arp_reply();*/
            break;
        default:
            fprintf(stderr, "Error in ARP type, dropping packet.\n");
            return;
        }
    }
}

void sr_handlepacket_arp_request(struct sr_instance* sr,
                                 uint8_t * packet/* lent */,
                                 unsigned int len,
                                 struct sr_if* recv_interface,
                                 sr_ethernet_hdr_t *ehdr,
                                 sr_arp_hdr_t *ahdr)
{
    /* Verify if ARP request is for the right IP */
    if (ahdr->ar_tip != recv_interface->ip)
    {
        fprintf(stderr, "Request not for correct interface, dropping packet.\n");
        return;
    }
    else
    {
        /*
        function handle_arpreq(req):
           if difftime(now, req->sent) > 1.0
               if req->times_sent >= 5:
                   send icmp host unreachable to source addr of all pkts waiting on this request
                   arpreq_destroy(req)
               else:
                   send arp request
                   req->sent = now
                   req->times_sent++
        */

        /* Create new reply packet */
        uint8_t *packet_rep = (uint8_t *) malloc(len);

        /* Get hdr from packet */
        sr_ethernet_hdr_t *ehdr_rep = (sr_ethernet_hdr_t*) packet_rep;
        sr_arp_hdr_t *ahdr_rep = (sr_arp_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t));

        /* Update all fields of packet */
        ahdr_rep->ar_hln = ahdr->ar_hln;
        ahdr_rep->ar_hrd = ahdr->ar_hrd;
        ahdr_rep->ar_op = htons(arp_op_reply);
        ahdr_rep->ar_pln = ahdr->ar_pln;
        ahdr_rep->ar_pro = ahdr->ar_pro;
        ahdr_rep->ar_sha;

        print_hdr_arp(ahdr_rep);
    }
}
