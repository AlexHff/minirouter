#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_handlepacket_arp.h"
#include "sr_handlepacket_ip.h"
#include <string.h>

void sr_handlepacket_ip(struct sr_instance* sr,
                         uint8_t * packet,
                         unsigned int len,
                         char *interface)
{
    /* Verify IP packet is of correct length*/
    int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if (len < minlength) {
        fprintf(stderr, "Failed to handle ip packet, insufficient length\n");
        return;
    }

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Check if packet is for router's interface */
    struct sr_if *interface_list = sr->if_list;
    int for_router = 0;
    while(interface_list != NULL)
    {
        if(iphdr->ip_dst == interface_list->ip) {
            for_router = 1;
            printf("FOR ROUTER\n");
            /* Find type of IP */            
            if (iphdr->ip_p == ip_protocol_icmp) {
                printf("ICMP\n");
                sr_handlepacket_icmp(sr, packet, len, iphdr, interface);
            }
            else 
            if ((iphdr->ip_p == ip_protocol_tcp) || (iphdr->ip_p == ip_protocol_udp)) {
                printf("UDP/TCP\n");
                sr_handlepacket_tcp_udp(sr, packet, iphdr, interface);
            }
            else {
                printf("Unknown protocol, dropping packet\n");
            }
        }
        interface_list = interface_list->next;
    }

    /* Packet is not for router, fwd */
    if(for_router == 0) {
        /* Check if ttl is correct */
        if (iphdr->ip_ttl == 1) {
            printf("TTL=1, ");
            sr_handlepacket_ttl_exceeded(sr, packet, iphdr, interface);
        }
        else {
             printf("not for the router, forwarding\n");
             sr_handle_forwarding(sr, packet, len, iphdr, interface);
        }
    }
}

void sr_handlepacket_icmp(struct sr_instance* sr,
                         uint8_t *packet,
                         unsigned int len,
                         sr_ip_hdr_t *iphdr,
                         char *interface)
{
    /* Verifiy checksum ICMP */
    uint16_t sum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    if (sum != cksum(iphdr, sizeof(sr_ip_hdr_t))) {
        fprintf(stderr, "Failed to handle icmp packet, checksum does not match\n");
        return;
    }
    else {
        iphdr->ip_sum = sum;
        sr_icmp_t11_hdr_t *icmphdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        if (icmphdr->icmp_type == icmp_type_echo_request) {
            if(icmphdr->icmp_code != 0x0000) {
                fprintf(stderr, "Error in icmp code field\n");
                return;
            }
            else {
                send_icmp_packet_reply(sr, packet, len, interface, iphdr, icmphdr);
            }
        }
        
    }
}

void send_icmp_packet_reply(struct sr_instance* sr, uint8_t *packet, unsigned int len,
                    char *interface, sr_ip_hdr_t *iphdr, sr_icmp_t11_hdr_t *icmphdr)
{
    /* Router's interface */
    struct sr_if *send_interface = sr_get_interface(sr, interface);

    /* Get eth hdr from packet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;
    
    /** ETH HDR **/
    /* Inverse sender/target MAC address */
    memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
    ehdr->ether_type = htons(ethertype_ip);

    /** IP HDR **/
    /* Set sender and receiver IP */
    iphdr->ip_dst = iphdr->ip_src;
    iphdr->ip_src = send_interface->ip;
    iphdr->ip_ttl = 100;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

    /** ICMP HDR **/
    icmphdr->icmp_type = icmp_type_echo_reply;
    icmphdr->icmp_code = icmphdr->icmp_code;
    icmphdr->icmp_sum = 0;
    icmphdr->icmp_sum = cksum(icmphdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    /* Send packet */
    sr_send_packet(sr, packet, len, send_interface->name);
    printf("Sending ICMP echo reply of length %d \n", len);
}

void sr_handlepacket_tcp_udp(struct sr_instance* sr, uint8_t *packet, sr_ip_hdr_t *iphdr,
                         char *interface)
{
    /* Create new reply packet */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *packet_rep = (uint8_t *) malloc(len);

    /* Router's interface */
    struct sr_if *send_interface = sr_get_interface(sr, interface);

    /* Get hdr from packet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;

    /* Create new hdrs */
    sr_ethernet_hdr_t *ehdr_rep = (sr_ethernet_hdr_t*) packet_rep;
    sr_ip_hdr_t *iphdr_rep = (sr_ip_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t11_hdr_t *icmphdr_rep = (sr_icmp_t11_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /** ETH HDR **/
    /* Inverse sender/target MAC address */
    memcpy(ehdr_rep->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr_rep->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
    ehdr_rep->ether_type = ntohs(ethertype_ip);

    /** IP HDR **/
    /* Sender and receiver IP */
    iphdr_rep->ip_dst = iphdr->ip_src;
    iphdr_rep->ip_src = send_interface->ip;
    iphdr_rep->ip_v = iphdr->ip_v;
    iphdr_rep->ip_hl = iphdr->ip_hl;
    iphdr_rep->ip_id = 0;
    iphdr_rep->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    iphdr_rep->ip_off = htons(IP_DF);
    iphdr_rep->ip_p = ip_protocol_icmp;
    iphdr_rep->ip_tos = iphdr->ip_tos;
    iphdr_rep->ip_ttl = INIT_TTL;
    iphdr_rep->ip_sum = 0;
    iphdr_rep->ip_sum = cksum(iphdr_rep, sizeof(sr_ip_hdr_t));

    /** ICMP HDR **/
    icmphdr_rep->icmp_type = icmp_type_destination_unreachable;
    icmphdr_rep->icmp_code = icmp_code_port_unreachable;
    memcpy(icmphdr_rep->data, iphdr, ICMP_DATA_SIZE);
    icmphdr_rep->icmp_sum = 0;
    icmphdr_rep->icmp_sum = cksum(icmphdr_rep, sizeof(sr_icmp_t11_hdr_t));

    /* Send packet */
    sr_send_packet(sr, packet_rep, len, send_interface->name);
    printf("Sending ICMP host unreachable of length %d \n", len);
}

void sr_handlepacket_ttl_exceeded(struct sr_instance* sr, uint8_t *packet, sr_ip_hdr_t *iphdr,
                         char *interface)
{
    /* Create new reply packet */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *packet_rep = (uint8_t *) malloc(len);

    /* Router's interface */
    struct sr_if *send_interface = sr_get_interface(sr, interface);

    /* Get hdr from packet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;

    /* Create new hdrs */
    sr_ethernet_hdr_t *ehdr_rep = (sr_ethernet_hdr_t*) packet_rep;
    sr_ip_hdr_t *iphdr_rep = (sr_ip_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t11_hdr_t *icmphdr_rep = (sr_icmp_t11_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Copy data of original ip hdr */
    memcpy(iphdr_rep, iphdr, sizeof(sr_ip_hdr_t));

    /** ETH HDR **/
    /* Inverse sender/target MAC address */
    memcpy(ehdr_rep->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr_rep->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
    ehdr_rep->ether_type = ntohs(ethertype_ip);

    /** IP HDR **/
    /* Sender and receiver IP */
    iphdr_rep->ip_dst = iphdr->ip_src;
    iphdr_rep->ip_src = send_interface->ip;
    iphdr_rep->ip_v = iphdr->ip_v;
    iphdr_rep->ip_hl = iphdr->ip_hl;
    iphdr_rep->ip_id = 0;
    iphdr_rep->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    iphdr_rep->ip_off = htons(IP_DF);
    iphdr_rep->ip_p = ip_protocol_icmp;
    iphdr_rep->ip_tos = iphdr->ip_tos;
    iphdr_rep->ip_ttl = INIT_TTL;
    iphdr_rep->ip_sum = 0;
    iphdr_rep->ip_sum = cksum(iphdr_rep, sizeof(sr_ip_hdr_t));

    /** ICMP HDR **/
    icmphdr_rep->icmp_type = icmp_type_time_exceeded;
    icmphdr_rep->icmp_code = icmp_code_ttl_exceeded;
    icmphdr_rep->unused = 0;
    memcpy(icmphdr_rep->data, iphdr, sizeof(sr_ip_hdr_t)+8);
    icmphdr_rep->icmp_sum = 0;
    icmphdr_rep->icmp_sum = cksum(icmphdr_rep, sizeof(sr_icmp_t11_hdr_t));

    /* Send packet */
    sr_send_packet(sr, packet_rep, len, send_interface->name);
    printf("sending ICMP TTL exceeded of length %d \n", len);
}

void sr_handle_forwarding(struct sr_instance* sr, uint8_t *packet, unsigned int len,
                        sr_ip_hdr_t *iphdr, char *interface)
{
    struct sr_rt *rtable = sr->routing_table;
    while(rtable) {
        if ((rtable->dest.s_addr & rtable->mask.s_addr) == (iphdr->ip_dst & rtable->mask.s_addr)) {
            struct sr_if *send_interface = sr_get_interface(sr, rtable->interface);
            printf("Found destination via interface %s\n", rtable->interface);

            struct sr_arpentry *next_hop = sr_arpcache_lookup(&(sr->cache), iphdr->ip_dst);
            
            if (next_hop != NULL) {
                /* Set eth hdr */
                sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;
                memcpy(ehdr->ether_dhost, next_hop->mac, ETHER_ADDR_LEN);
                memcpy(ehdr->ether_shost, send_interface->addr, ETHER_ADDR_LEN);
                sr_send_packet(sr, packet, len, send_interface->name);
                free(next_hop);
            }
            else {
                printf("searching for next hop\n");
                /* Store packet in arpcache */
                struct sr_arpreq *arpreq = sr_arpcache_queuereq(&sr->cache, iphdr->ip_dst, packet, len, send_interface->name);
                handle_arpreq(sr, arpreq);
            }
            return;
        }
        rtable = rtable->next;
    }
}