#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_handlepacket_arp.h"
#include <string.h>

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
        struct sr_arpreq *recv_arp = sr_arpcache_insert(&sr->cache, ahdr->ar_sha, ahdr->ar_sip);

        /* Verify if ARP request is for the right IP */
        if (ahdr->ar_tip == recv_interface->ip)
        {
            /* Find ARP type to proceed appropriately */
            switch(arptype(ahdr))
            {
            case arp_op_request:
                printf("request\n");
                sr_handlepacket_arp_request(sr, packet, len, recv_interface, ehdr, ahdr, interface);
                break;
            case arp_op_reply:
                printf("reply\n");
                sr_handlepacket_arp_reply(sr, packet, len, recv_interface, interface, recv_arp);
                break;
            default:
                fprintf(stderr, "Unknown ARP type, dropping packet.\n");
                return;
            }
        }
        else
        {
            fprintf(stderr, "Packet not for correct interface, dropping packet.\n");
            return;
        }
    }
}

void sr_handlepacket_arp_request(struct sr_instance* sr,
                                 uint8_t * packet/* lent */,
                                 unsigned int len,
                                 struct sr_if* recv_interface,
                                 sr_ethernet_hdr_t *ehdr,
                                 sr_arp_hdr_t *ahdr,
                                 char* interface)
{
    /* Create new reply packet */
    uint8_t *packet_rep = (uint8_t *) malloc(len);

    /* Get hdr from packet */
    sr_ethernet_hdr_t *ehdr_rep = (sr_ethernet_hdr_t*) packet_rep;
    sr_arp_hdr_t *ahdr_rep = (sr_arp_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t));

    /** ARP HDR **/
    /* All these fields are the same for the reply */
    ahdr_rep->ar_hln = ahdr->ar_hln;
    ahdr_rep->ar_hrd = ahdr->ar_hrd;
    ahdr_rep->ar_op = htons(arp_op_reply);
    ahdr_rep->ar_pln = ahdr->ar_pln;
    ahdr_rep->ar_pro = ahdr->ar_pro;

    /* Inverse sender/target hardware address */
    memset(ahdr_rep->ar_tha, '\0', sizeof(ahdr_rep->ar_tha));
    strcpy(ahdr_rep->ar_tha, ahdr->ar_sha);
    memset(ahdr_rep->ar_sha, '\0', sizeof(ahdr_rep->ar_sha));
    strcpy(ahdr_rep->ar_sha, recv_interface->addr);

    /* Inverse sender/target ip address */
    ahdr_rep->ar_tip = ahdr->ar_sip;
    ahdr_rep->ar_sip = ahdr->ar_tip;

    /** ETH HDR **/
    /* Inverse sender/target MAC address */
    memset(ehdr_rep->ether_dhost, '\0', sizeof(ehdr_rep->ether_dhost));
    strcpy(ehdr_rep->ether_dhost, ehdr->ether_shost);
    memset(ehdr_rep->ether_shost, '\0', sizeof(ehdr_rep->ether_shost));
    strcpy(ehdr_rep->ether_shost, recv_interface->addr);

    ehdr_rep->ether_type = ntohs(ethertype_arp);

    /* Send packet */
    sr_send_packet(sr, packet_rep, len, interface);
    printf("Sending ARP reply of length %d \n", len);
}

void sr_handlepacket_arp_reply(struct sr_instance* sr,
                                 uint8_t * packet/* lent */,
                                 unsigned int len,
                                 struct sr_if* recv_interface,
                                 char* interface,
                                 struct sr_arpreq *recv_arp)
{
    
    if(!recv_arp)
    {
        fprintf(stderr, "Error recv_arp\n");
        return;
    }
    else
    {
        /* Packet queue */
        struct sr_packet *packet_queue = recv_arp->packets;
        
        /* Run through queue */
        unsigned int i;
        for(i = 0; i < sizeof(packet_queue); ++i)
        {
            printf("hello\n");
        }
    }
}