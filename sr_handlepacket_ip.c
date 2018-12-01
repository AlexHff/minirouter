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
        sr_icmp_t11_hdr_t *icmphdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        if (icmphdr->icmp_type == icmp_type_echo_request) {
            if(icmphdr->icmp_code != 0x0000) {
                fprintf(stderr, "Error in icmp code field\n");
                return;
            }
            else {
                print_hdrs(packet, len);
                send_icmp_packet_reply(sr, packet, interface, iphdr, icmphdr);
            }
        }
        
    }
}

void send_icmp_packet_reply(struct sr_instance* sr, uint8_t *packet,
                    char *interface, sr_ip_hdr_t *iphdr, sr_icmp_t11_hdr_t *icmphdr)
{
    /* Create new reply packet */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *packet_rep = (uint8_t *) malloc(len);

    /* Router's interface */
    struct sr_if *send_interface = sr_get_interface(sr, interface);

    /* Get hdr from packet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t*) packet;
    sr_ethernet_hdr_t *ehdr_rep = (sr_ethernet_hdr_t*) packet_rep;
    sr_ip_hdr_t *iphdr_rep = (sr_ip_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t11_hdr_t *icmphdr_rep = (sr_icmp_t11_hdr_t *)(packet_rep + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /** ETH HDR **/
    /* Inverse sender/target MAC address */
    memset(ehdr_rep->ether_dhost, '\0', sizeof(ehdr_rep->ether_dhost));
    strcpy(ehdr_rep->ether_dhost, ehdr->ether_shost);
    memset(ehdr_rep->ether_shost, '\0', sizeof(ehdr_rep->ether_shost));
    strcpy(ehdr_rep->ether_shost, send_interface->addr);
    ehdr_rep->ether_type = ntohs(ethertype_ip);

    /** IP HDR **/
    /* Sender and receiver IP */
    iphdr_rep->ip_dst = iphdr->ip_src;
    iphdr_rep->ip_src = send_interface->ip;
    iphdr_rep->ip_v = iphdr->ip_v;
    iphdr_rep->ip_hl = iphdr->ip_hl;
    iphdr_rep->ip_id = iphdr->ip_id;
    iphdr_rep->ip_len = iphdr->ip_len;
    iphdr_rep->ip_off = iphdr->ip_off;
    iphdr_rep->ip_p = iphdr->ip_p;
    iphdr_rep->ip_tos = iphdr->ip_tos;
    iphdr_rep->ip_ttl = iphdr->ip_ttl - 1;
    iphdr_rep->ip_sum = 0;
    iphdr_rep->ip_sum = cksum(iphdr_rep, sizeof(sr_ip_hdr_t));

    icmphdr_rep->icmp_type = icmp_type_echo_reply;
    icmphdr_rep->icmp_code = icmphdr->icmp_code;
    icmphdr_rep->icmp_sum = 0;
    icmphdr_rep->icmp_sum = cksum(icmphdr_rep, sizeof(sr_icmp_t11_hdr_t));

    /* Send packet */
    sr_send_packet(sr, packet_rep, len, send_interface->name);
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
    memset(ehdr_rep->ether_dhost, '\0', sizeof(ehdr_rep->ether_dhost));
    strcpy(ehdr_rep->ether_dhost, ehdr->ether_shost);
    memset(ehdr_rep->ether_shost, '\0', sizeof(ehdr_rep->ether_shost));
    strcpy(ehdr_rep->ether_shost, send_interface->addr);
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
    icmphdr_rep->icmp_type = icmp_type_echo_reply;
    icmphdr_rep->icmp_code = icmphdr->icmp_code;
    icmphdr_rep->icmp_sum = 0;
    icmphdr_rep->icmp_sum = cksum(icmphdr_rep, sizeof(sr_icmp_t11_hdr_t));

    /* Send packet */
    sr_send_packet(sr, packet_rep, len, send_interface->name);
    printf("Sending ICMP host unreachable of length %d \n", len);
}