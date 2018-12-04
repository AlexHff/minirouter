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
    Traceroute was definitely the most complexe aspect of the project. The first step is to 
send an ICMP TTL exceeded for the first packet received. This is implmented in 
sr_handlepacket_ip.c. If the TTL is good, forward the packet. Now we need to check if the MAC 
address of the next hop is in our ARP cache. If it is, just send the packet, change eth hdr. 
If it's not, we have to store the packet in a stack and send an ARP request to the correct 
IP. When the ARP reply comes back, we can handle all the packet in the queue. Now since the 
queue is a stack, we first need to convert it into an array to access the first element that 
got to the router. Indeed, we need to respect the FIFO principle. All of this is implemented 
in sr_handle_forwarding in sr_handlepacket_ip.c and in sr_arpcache.c. The header was very 
helpful since it gave pseudo-code for the implementation of some methods.

    The router must respond correctly to ICMP echo requests.
    ICMP echo request are directed to the router. In this case, we just check that the packet 
is good hence the ip header checksum is correct and the icmp type and code is good, then we 
take that same packet and modify element in the header and send it back.

    The router must handle TCP/UDP packets sent to one of its interfaces. In this case the 
router should respond with an ICMP port unreachable.
    For this, just check the type of IP and if it's for the router. If both this conditions 
are valid, verify that the packet is not corrupted by computing the checksum of the ip 
header. If everything is good, we just create a new ICMP packet in the method 
sr_handlepacket_tcp_udp(). Here, we just create an ICMP host unreachable packet for the 
source of the UDP/TCP packet.

    The router must maintain an ARP cache whose entries are invalidated after a timeout 
period (timeouts should be on the order of 15 seconds).
    All the methods related to the ARP cache are implemented in sr_arpcache.c. Here I just 
converted the pseudo-code given in the header into C code.

    The router must queue all packets waiting for outstanding ARP replies. If a host does not 
respond to 5 ARP requests, the queued packet is dropped and an ICMP host unreachable message 
is sent back to the source of the queued packet.
    See previous requirement.

    The router must not needlessly drop packets (for example when waiting for an ARP reply)
    All the packets are stored in a queue if they can not be sent out immediately.

    The router must enforce guarantees on timeouts--that is, if an ARP request is not 
responded to within a fixed period of time, the ICMP host unreachable message is generated 
even if no more packets arrive at the router. (Note: You can guarantee this by implementing 
the sr_arpcache_sweepreqs function in sr_arpcache.c correctly.)
    
