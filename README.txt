Name: Alexander Hoffmann
PID: U08115448

Required Functionality

    The router must successfully route packets between the Internet and the application 
servers.
    The method sr_handle_forwarding() in sr_handlepacket_ip.c routes any type of packet from 
the client to one of the hosts. To find the destination, we get the routing table from the 
current instance and compute the LPM. Then, get the sender interface and the arpcache to find 
if we already have the MAC address of our next hop. If we have, modify the header and send 
packet. If we don't have, we go to handle_arpreq() which will send an ARP request to the next 
hop.
    
    The router must correctly handle ARP requests and replies.
    When we get a packet, check if it's ARP type. Then verifiy what kind or ARP. If ARP 
request, then sr_handlepacket√_arp_request() in sr_handlepacket_arp.c will create a new reply 
packet with the MAC address of the current interface. If it's an ARP reply, we check the 
queue associated to the request we sent earlier. After that, we send every packet of the 
queue respecting the FIFO principle. This was probably one of the hardest parts because it 
wasn't clear how the packets were added to the queue. It turns out it's a stack following 
LIFO principle. Therefore, I had to create an array inversing every element of the stack to 
send out the packets in the correct order.

    The router must correctly handle traceroutes through it (where it is not the end host) 
and to it (where it is the end host).
    Traceroute was definitely the most complexe aspect of the project. 

    The router must respond correctly to ICMP echo requests.
    The router must handle TCP/UDP packets sent to one of its interfaces. In this case the 
router should respond with an ICMP port unreachable.
    The router must maintain an ARP cache whose entries are invalidated after a timeout 
period (timeouts should be on the order of 15 seconds).
    The router must queue all packets waiting for outstanding ARP replies. If a host does not 
respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message 
is sent back to the source of the queued packet.
    The router must not needlessly drop packets (for example when waiting for an ARP reply)
    The router must enforce guarantees on timeouts--that is, if an ARP request is not 
responded to within a fixed period of time, the ICMP host unreachable message is generated 
even if no more packets arrive at the router. (Note: You can guarantee this by implementing 
the sr_arpcache_sweepreqs function in sr_arpcache.c correctly.)
