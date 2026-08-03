#include "decoder.h"
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_LEN 14

int decode_packet(const u_char* packet,
                  const struct pcap_pkthdr* header,
                  PacketInfo* out) {
    memset(out, 0, sizeof(PacketInfo));
    out->timestamp = header->ts;
    out->length    = header->len;

    if (header->len < ETHERNET_HEADER_LEN) return 0;

    // Step 1: Ethernet header
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;

    // Step 2: IP header
    struct ip* ip_hdr = (struct ip*)(packet + ETHERNET_HEADER_LEN);
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    if (ip_hdr_len < 20) return 0;

    strncpy(out->src_ip, inet_ntoa(ip_hdr->ip_src), 15);
    strncpy(out->dst_ip, inet_ntoa(ip_hdr->ip_dst), 15);

    const u_char* transport = packet + ETHERNET_HEADER_LEN + ip_hdr_len;

    // Step 3: TCP or UDP
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)transport;
        out->src_port  = ntohs(tcp->th_sport);
        out->dst_port  = ntohs(tcp->th_dport);
        strncpy(out->protocol, "TCP", 4);
        out->is_syn     = (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
        out->is_syn_ack = (tcp->th_flags & TH_SYN) &&  (tcp->th_flags & TH_ACK);
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)transport;
        out->src_port = ntohs(udp->uh_sport);
        out->dst_port = ntohs(udp->uh_dport);
        strncpy(out->protocol, "UDP", 4);
    } else {
        strncpy(out->protocol, "???", 4);
    }
    return 1;
}
