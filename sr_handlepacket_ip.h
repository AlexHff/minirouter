#ifndef SR_HANDLEPACKET_IP_H
#define SR_HANDLEPACKET_IP_H

void sr_handlepacket_ip(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_handlepacket_icmp(struct sr_instance*, uint8_t *, unsigned int,
                            sr_ip_hdr_t *, char *);
void send_icmp_packet_reply(struct sr_instance* , uint8_t *, char *,
                            sr_ip_hdr_t *, sr_icmp_t11_hdr_t *);
void sr_handlepacket_tcp_udp(struct sr_instance* , uint8_t *,
                            sr_ip_hdr_t *, char *);

#endif
