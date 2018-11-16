#ifndef SR_HANDLEPACKET_ARP_H
#define SR_HANDLEPACKET_ARP_H

void sr_handlepacket_arp(struct sr_instance* , uint8_t * , unsigned int , char* );
void sr_handlepacket_arp_request(struct sr_instance* , uint8_t * , unsigned int , char*, sr_ethernet_hdr_t*, sr_arp_hdr_t*);

#endif
