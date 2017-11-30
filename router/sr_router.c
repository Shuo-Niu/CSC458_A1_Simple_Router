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
            /* not necessary to recalculate checksum here */

            /* construct ICMP header */
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
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
            /* if code == 3 (i.e. UDP arrives destination), set source IP to received packet's destination IP */
            /* if others, set source IP to outgoing interface's IP */
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

/* Custom method: handle ARP packet */
void handle_arp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    printf("Received ARP packet.\n");

    /* store the content of the ARP hdr (bypass the Ethernet hdr) */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* verify hardware format code */
    if(ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        printf("Error: handle_arp: packet is not an Ethernet frame.\n");
        return;
    }

    /* verify Ethernet protocol type */
    if(ntohs(arp_hdr->ar_pro) != ethertype_ip) {
        printf("Error: handle_arp: packet is not an IP packet.\n");
        return;
    }

    /* verify that destination IP is on this router */
    struct sr_if* out_interface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
    if(!out_interface) {
        printf("Error: handle_arp: destination IP not on this router.\n");
        return;
    }

    switch(ntohs(arp_hdr->ar_op)) {
        case arp_op_request: {
            printf("Received ARP packet - ARP request.\n");

            /* store the incoming interface */
            struct sr_if* in_interface = sr_get_interface(sr, interface);

            /* copy the ARP request */
            uint8_t* arp_req = malloc(len);
            memcpy(arp_req, packet, len);

            /* construct Ethernet hdr */
            sr_ethernet_hdr_t* arp_req_eth_hdr = (sr_ethernet_hdr_t*)arp_req;
            /* set destination MAC to be source MAC */
            memcpy(arp_req_eth_hdr->ether_dhost, arp_req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
            /* set source MAC to be incoming interface's MAC */
            memcpy(arp_req_eth_hdr->ether_shost, in_interface, ETHER_ADDR_LEN);

            /* construct ARP hdr */
            sr_arp_hdr_t* arp_req_arp_hdr = (sr_arp_hdr_t*)(arp_req + sizeof(sr_ethernet_hdr_t));
            arp_req_arp_hdr->ar_op = htons(arp_op_reply);
            /* set sender MAC to be incoming interface's MAC */
            memcpy(arp_req_arp_hdr->ar_sha, in_interface->addr, ETHER_ADDR_LEN);
            /* set sender IP to be incoming interface's IP */
            arp_req_arp_hdr->ar_sip = in_interface->ip;
            /* set target MAC to be received packet's sender MAC */
            memcpy(arp_req_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            /* set target IP to be received packet's sender IP */
            arp_req_arp_hdr->ar_tip = arp_hdr->ar_sip;

            send_packet(sr, arp_req, len, in_interface, arp_hdr->ar_sip);
            free(arp_req);

            break;
        }
        case arp_op_reply: {
            printf("Received ARP packet - ARP reply.\n");

            struct sr_arpreq* cached = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            if(cached) {
                struct sr_packet* packet = cached->packets;

                struct sr_if* in_interface;
                sr_ethernet_hdr_t* eth_hdr;

                while(packet) {
                    in_interface = sr_get_interface(sr, packet->iface);
                    if(in_interface) {
                        /* construct Ethernet hdr */
                        eth_hdr = (sr_ethernet_hdr_t*)(packet->buf);
                        /* set destination MAC to be received packet's sender MAC */
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        /* set source MAC to be incoming interface's MAC */
                        memcpy(eth_hdr->ether_shost, in_interface->addr, ETHER_ADDR_LEN);

                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                    }
                    packet = packet->next;
                }
                sr_arpreq_destroy(&sr->cache, cached);
            }
            break;
        }
    }
}

/* Custom method: handle IP packet */
void handle_ip(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    printf("Received IP packet.\n");

    /* store the content of the packet (bypass the Ethernet hdr) */
    uint8_t* payload = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) payload;

    /* verify the IP hdr */
    if(verify_ip(ip_hdr) == -1) {
        return;
    }

    /* check if packet's destination is this router */
    struct sr_if* out_interface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    if(out_interface) {
        printf("Packet destined to this router.\n");

        switch(ip_hdr->ip_p) {
            case ip_protocol_icmp: {
                printf("Packet is an ICMP message.\n");

                if(verify_icmp(packet, len) == -1) {
                    return;
                }

                sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* handle 'ping' echo request */
                if(icmp_hdr->icmp_type == icmp_type_echo_request) {
                    send_icmp_msg(sr, packet, len, icmp_type_echo_reply, (uint8_t)0);
                }

                break;
            }
            case ip_protocol_tcp:
            case ip_protocol_udp: {
                printf("Packet is a TCP/UDP message.\n");
                /* send ICMP msg - type 3 code 3 */
                send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
                break;
            }
        }
    } else {
        printf("Packet destined elsewhere.\n");

        /* construct IP hdr (bypass Ethernet hdr) */
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

        /* decrease TTL */
        ip_hdr->ip_ttl--;
        if(ip_hdr->ip_ttl == 0) {
            printf("TTL decreased to zero.\n");
            send_icmp_msg(sr, packet, len, icmp_type_time_exceeded, (uint8_t)0);
            return;
        }

        /* recalculate checksum */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        /* lookup destination IP in routing table */
        struct sr_rt* table_entry = longest_matching_prefix(sr, ip_hdr->ip_dst);
        if(!table_entry) {
            printf("Error: handle_ip: destination IP not existed in routing table.\n");
            send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
            return;
        }

        /* find routing table indicated interface */
        struct sr_if* rt_out_interface = sr_get_interface(sr, table_entry->interface);
        if(!rt_out_interface) {
            printf("Error: handle_ip: interface \'%s\' not found.\n", table_entry->interface);
            return;
        }

        send_packet(sr, packet, len, rt_out_interface, table_entry->gw.s_addr);
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

    switch (ethertype(packet)) {
        /* ARP packet */
        case ethertype_arp: {
            handle_arp(sr, packet, len, interface);
            break;
        }
        /* IP packet */
        case ethertype_ip: {
            handle_ip(sr, packet, len, interface);
            break;
        }
    }
}/* end sr_ForwardPacket */

