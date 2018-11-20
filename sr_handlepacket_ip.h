#ifndef SR_HANDLEPACKET_IP_H
#define SR_HANDLEPACKET_IP_H

void sr_handlepacket_ip(struct sr_instance*, uint8_t *, unsigned int);
void sr_handlepacket_icmp(struct sr_instance*, uint8_t *, unsigned int,
                            sr_ip_hdr_t *);

#endif
