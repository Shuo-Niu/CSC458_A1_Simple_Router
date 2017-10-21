/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/* Custom method: send packet to next_hop_ip, according to "sr_arpcache.h"
 * Check the ARP cache, send packet or send ARP request */
void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* interface, uint32_t dest_ip) {
    struct sr_arpentry* arp_cached = sr_arpcache_lookup(&sr->cache, dest_ip);

    if(arp_cached) {
        /* if cached, send packet through outgoing interface */
        printf("ARP mapping cached.\n");
        sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
        /* set destination MAC to the mapped MAC */
        memcpy(ehdr->ether_dhost, arp_cached->mac, ETHER_ADDR_LEN);
        /* set the source MAC to the outgoing interface's MAC */
        memcpy(ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, interface->name);
        free(arp_cached);
    } else {
        /* if not cached, send ARP request */
        printf("Queue ARP request.\n");
        struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
        handle_arpreq(sr, arpreq);
    }
}

/* Custom method: send an ICMP message */
void send_icmp_msg(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code) {
    /* New packet illustration:
                |<- Ethernet hdr ->|<- IP hdr ->|<- ICMP hdr ->|
                ^
             *packet
    */
    /* construct ethernet header from packet */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;
    /* construct IP header from packet */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* get longest matching prefix of source IP */
    struct sr_rt* rt_entry = longest_matching_prefix(sr, ip_hdr->ip_src);

    if(!rt_entry) {
        printf("Error: send_icmp_msg: routing table entry not found.\n");
        return;
    }

    /* get outgoing interface */
    struct sr_if* interface = sr_get_interface(sr, rt_entry->interface);

    switch(type) {
        case icmp_type_echo_reply: {
            /* set ethernet header source MAC & destination MAC: 00-00-00-00-00-00 */
            memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

            /* this ICMP message is a sending-back */
            uint32_t temp = ip_hdr->ip_dst;
            ip_hdr->ip_dst = ip_hdr->ip_src;
            ip_hdr->ip_src = temp;

            /* construct ICMP header, length of type 0 ICMP header is four times IP header length */
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;

            /* compute ICMP checksum */
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
            
            send_packet(sr, packet, len, interface, rt_entry->gw.s_addr);
            break;
        }
        case icmp_type_time_exceeded:
        case icmp_type_dest_unreachable: {
            /* calculate length of the new ICMP packet (illustrated above) */
            unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            /* construct new ICMP packet */
            uint8_t* new_packet = malloc(new_len);

            /* sanity check */
            assert(new_packet);

            /* construct ethernet hdr */
            sr_ethernet_hdr_t* new_eth_hdr = (sr_ethernet_hdr_t*)new_packet;
            /* construct IP hdr */
            sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
            /* construct type 3 ICMP hdr */
            sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

             /* set new ethernet header source MAC & destination MAC: 00-00-00-00-00-00 */
            memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
            /* set protocol type to IP */
            new_eth_hdr->ether_type = htons(ethertype_ip);

            /* set new IP hdr */
            new_ip_hdr->ip_v    = 4;
            new_ip_hdr->ip_hl   = sizeof(sr_ip_hdr_t) / 4;
            new_ip_hdr->ip_tos  = 0;
            new_ip_hdr->ip_len  = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            new_ip_hdr->ip_id   = htons(0);
            new_ip_hdr->ip_off  = htons(IP_DF);
            new_ip_hdr->ip_ttl  = 255;
            new_ip_hdr->ip_p    = ip_protocol_icmp;
            /* if code == 3 (UDP arrives destination), set source IP to received packet's destination IP */
            /* if TTL exceeded, set source IP to outgoing interface's IP */
            new_ip_hdr->ip_src = code == icmp_dest_unreachable_port ? ip_hdr->ip_dst : interface->ip;
            /* set destination IP to received packet's source IP */
            new_ip_hdr->ip_dst = ip_hdr->ip_src;

            /* recalculate checksum */
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            /* set type 3 ICMP hdr */
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            send_packet(sr, new_packet, new_len, interface, rt_entry->gw.s_addr);
            free(new_packet);
            break;
        }
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d\n", len);

    /* fill in code here */

    /* sanity check the incoming Ethernet packet */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        printf("Error: sr_handlepacket: Ethernet packet too short.\n");
        return;
    }

    /* store the incoming interface */
    struct sr_if* in_interface = sr_get_interface(sr, interface);

    /* store the contents of the packet (bypass the Ethernet header) */
    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));

    /* TODO: eventually break this out into separate methods */
    switch (ethertype(packet)) {
        /* ARP packet */
        case ethertype_arp: {
            printf("ARP: received packet\n");

            sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)payload;

            /* Ensure we have an ethernet packet */
            if (ntohs(arphdr->ar_hrd) != arp_hrd_ethernet) {
                printf("ARP: not an ethernet frame\n");
                return;
            }

            /* Ensure we have an IP packet */
            if (ntohs(arphdr->ar_pro) != ethertype_ip) {
                printf("ARP: not an IP packet\n");
            	return;
            }

            /* Check if destined for one of the router's interfaces */
            struct sr_if *dest = sr_get_interface_by_ip(sr, arphdr->ar_tip);

            /* Drop it if it's not for the router */
            if (!dest) {
                printf("ARP: not destined for router\n");
                return;
            }

            switch (ntohs(arphdr->ar_op)) {
                case arp_op_request: {
                    /* ARP request: reply back */
                    printf("ARP: received request\n");

                    /* Create copy of the request */
                    uint8_t *arpres = malloc(len);
                    memcpy(arpres, packet, len);

                    /* Update ethernet header */
                    sr_ethernet_hdr_t *arpres_ehdr = (sr_ethernet_hdr_t *)arpres;
                    /* Reply dest MAC address is request source MAC address */
                    memcpy(arpres_ehdr->ether_dhost, arpres_ehdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(arpres_ehdr->ether_shost, in_interface->addr, ETHER_ADDR_LEN);

                    /* Update ARP header */
                    sr_arp_hdr_t *arpres_arphdr = (sr_arp_hdr_t *)(arpres + sizeof(sr_ethernet_hdr_t));
                    arpres_arphdr->ar_op = htons(arp_op_reply);                     /* Reply operation */
                    memcpy(arpres_arphdr->ar_sha, in_interface->addr, ETHER_ADDR_LEN);      /* Source MAC address */
                    arpres_arphdr->ar_sip = in_interface->ip;                               /* Source IP address */
                    memcpy(arpres_arphdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);  /* Target MAC address */
                    arpres_arphdr->ar_tip = arphdr->ar_sip;                         /* Target IP address */

                    send_packet(sr, arpres, len, in_interface, arphdr->ar_sip);
                    free(arpres);

                    break;
                }

                case arp_op_reply: {
                    /* ARP reply: cache it */
                    printf("ARP: received reply\n");

                    struct sr_arpreq *cached = sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);

                    /* Send outstanding ARP packets */
                    if (cached) {
                        struct sr_packet *packet = cached->packets;

                        struct sr_if *interface = NULL;
                        sr_ethernet_hdr_t *ethernetHeader = NULL;

                        while (packet) {
                            interface = sr_get_interface(sr, packet->iface);

                            if (interface) {
                                /* Set src/dest MAC addresses */
                                ethernetHeader = (sr_ethernet_hdr_t *)(packet->buf);
                                memcpy(ethernetHeader->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);
                                memcpy(ethernetHeader->ether_shost, interface->addr, ETHER_ADDR_LEN);

                                sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                            }

                            packet = packet->next;
                        }

                        sr_arpreq_destroy(&sr->cache, cached);
                    }

                    break;
                }
            }

            break;
        }

        /* IP packet */
        case ethertype_ip: {
            printf("IP: received packet\n");

            sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)payload;

            /* Drop packet if it's invalid */
            if (verify_ip(iphdr) == -1) {
                return;
            }

            /* Check if destined for one of the router's interfaces */
            struct sr_if *dest = sr_get_interface_by_ip(sr, iphdr->ip_dst);

            if (dest) {
                printf("IP: destined for router\n");

                /* Destined for router: handle contained packet */
                switch (iphdr->ip_p) {
                    /* ICMP messages */
                    case ip_protocol_icmp: {
                        printf("IP: ICMP message\n");

                        /* Verify that header length is valid */
                        if (len < sizeof(sr_ethernet_hdr_t) + (iphdr->ip_hl * 4) + sizeof(sr_icmp_hdr_t)) {
                            printf("ICMP: insufficient header length\n");
                        }

                        sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)(payload + (iphdr->ip_hl * 4));

                        /* Verify that the ICMP checksum matches */
                        uint16_t old_cksum = icmphdr->icmp_sum;
                        icmphdr->icmp_sum = 0;
                        uint16_t new_cksum = cksum(icmphdr, ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4));
                        icmphdr->icmp_sum = old_cksum;
                        if (old_cksum != new_cksum) {
                            printf("ICMP: checksum didn't match\n");
                            return;
                        }

                        /* Handle "echo request" */
                        if (icmphdr->icmp_type == icmp_type_echo_request) {
                            send_icmp_msg(sr, packet, len, icmp_type_echo_reply, (uint8_t) 0);
                        }

                        break;
                    }

                    /* TCP/UDP: drop packet and send "destination unreachable" ICMP */
                    case ip_protocol_tcp:
                    case ip_protocol_udp: {
                        printf("IP: TCP/UDP message\n");
                        send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);

                        break;
                    }
                }
            } else {
                /* Forward the packet to its actual destination */
                printf("IP: destined elsewhere\n");

                /* Decrement TTL */
                iphdr->ip_ttl--;

                /* Send "Time exceeded" ICMP message if the TTL causes the packet to be dropped */
                if (iphdr->ip_ttl == 0) {
                    printf("IP: TTL decremented to 0 (sending ICMP time exceeded)\n");
                    send_icmp_msg(sr, packet, len, icmp_type_time_exceeded, (uint8_t) 0);
                    return;
                }

                /* Recompute checksum */
                iphdr->ip_sum = 0;
                iphdr->ip_sum = cksum(iphdr, iphdr->ip_hl * 4);

                /* Look up in routing table with longest matching prefix */
                struct sr_rt *route = longest_matching_prefix(sr, iphdr->ip_dst);

                if (!route) {
                    printf("No route found (sending ICMP net unreachable)\n");
                    send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
                    return;
                }

                struct sr_if *route_intf = sr_get_interface(sr, route->interface);
                if (!route_intf) {
                    printf("No interface found with name \"%s\"", route->interface);
                    return;
                }

                if (route) {
                    send_packet(sr, packet, len, route_intf, route->gw.s_addr);
                } else {
                    send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
                }
            }

            break;
        }
    }

}/* end sr_ForwardPacket */

