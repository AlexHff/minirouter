#include <stdio.h>
#include <assert.h>

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
    unsigned int i;
    int for_router = 0;
    for(i = 0; i < 3; i++)
    {
        if(iphdr->ip_dst == interface_list->ip) {
            for_router = 1;
            switch (iphdr->ip_p)
            {
                case ip_protocol_icmp:
                    printf("ICMP\n");
                    sr_handlepacket_icmp(sr, packet, len, iphdr, interface);
                    break;
                case ip_protocol_tcp:
                case ip_protocol_udp:
                    printf("UDP/TCP\n");
                    sr_handlepacket_tcp_udp(sr, packet, iphdr, interface);
                    break;
                default:
                printf("Unknown protocol, dropping packet\n");
                    break;
            }
        }
        interface_list = interface_list->next;
    }

    iphdr->ip_ttl = 1;
    /* Packet is not for router, fwd */
    if(for_router == 0) {
        /* Check if ttl is correct */
        if (iphdr->ip_ttl == 1) {
            printf("TTL=0, ");
            sr_handlepacket_ttl_exceeded(sr, packet, iphdr, interface);
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
    sr_icmp_t11_hdr_t *icmphdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

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
    sr_icmp_t11_hdr_t *icmphdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

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
    icmphdr_rep->icmp_type = icmp_type_time_exceeded;
    icmphdr_rep->icmp_code = icmp_code_ttl_exceeded;
    memcpy(icmphdr_rep->data, iphdr, ICMP_DATA_SIZE);
    icmphdr_rep->icmp_sum = 0;
    icmphdr_rep->icmp_sum = cksum(icmphdr, sizeof(sr_icmp_t11_hdr_t));

    /* Send packet */
    sr_send_packet(sr, packet_rep, len, send_interface->name);
    printf("sending ICMP TTL exceeded of length %d \n", len);
}