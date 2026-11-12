#include "decoder.h"
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_LEN 14
#define NULL_HEADER_LEN     4   // BSD/macOS loopback (DLT_NULL / DLT_LOOP)

int decoder_supports_linktype(int linktype) {
    return linktype == DLT_EN10MB || linktype == DLT_NULL || linktype == DLT_LOOP;
}

int decode_packet(const u_char* packet,
                  const struct pcap_pkthdr* header,
                  int linktype,
                  PacketInfo* out) {
    memset(out, 0, sizeof(PacketInfo));
    out->timestamp = header->ts;
    out->length    = header->len;

    // Step 1: link layer — work out where the IP header starts and which IP version it is
    size_t link_len;
    int ip_version;

    if (linktype == DLT_EN10MB) {
        if (header->caplen < ETHERNET_HEADER_LEN) return 0;
        const struct ether_header* eth = (const struct ether_header*)packet;
        uint16_t ether_type = ntohs(eth->ether_type);
        if (ether_type == ETHERTYPE_IP)        ip_version = 4;
        else if (ether_type == ETHERTYPE_IPV6) ip_version = 6;
        else return 0;
        link_len = ETHERNET_HEADER_LEN;
    } else if (linktype == DLT_NULL || linktype == DLT_LOOP) {
        // 4-byte address-family header whose byte order and values differ by OS,
        // so read the version nibble of the IP header instead.
        if (header->caplen < NULL_HEADER_LEN + 1) return 0;
        ip_version = packet[NULL_HEADER_LEN] >> 4;
        if (ip_version != 4 && ip_version != 6) return 0;
        link_len = NULL_HEADER_LEN;
    } else {
        return 0;
    }

    const u_char* ip_packet = packet + link_len;
    size_t ip_packet_len = header->caplen - link_len;
    uint8_t protocol;
    const u_char* transport;
    size_t transport_len;

    // Step 2: network layer
    if (ip_version == 4) {
        if (ip_packet_len < sizeof(struct ip)) return 0;
        const struct ip* ip_hdr = (const struct ip*)ip_packet;
        size_t ip_hdr_len = (size_t)ip_hdr->ip_hl * 4;
        if (ip_hdr->ip_v != 4 || ip_hdr_len < sizeof(struct ip) ||
            ip_hdr_len > ip_packet_len) return 0;

        if (inet_ntop(AF_INET, &ip_hdr->ip_src, out->src_ip,
                      sizeof(out->src_ip)) == NULL ||
            inet_ntop(AF_INET, &ip_hdr->ip_dst, out->dst_ip,
                      sizeof(out->dst_ip)) == NULL) return 0;

        protocol = ip_hdr->ip_p;
        transport = ip_packet + ip_hdr_len;
        transport_len = ip_packet_len - ip_hdr_len;
    } else { 
        if (ip_packet_len < sizeof(struct ip6_hdr)) return 0;
        const struct ip6_hdr* ip6_hdr = (const struct ip6_hdr*)ip_packet;

        if (inet_ntop(AF_INET6, &ip6_hdr->ip6_src, out->src_ip,
                      sizeof(out->src_ip)) == NULL ||
            inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, out->dst_ip,
                      sizeof(out->dst_ip)) == NULL) return 0;

        protocol = ip6_hdr->ip6_nxt;
        transport = ip_packet + sizeof(struct ip6_hdr);
        transport_len = ip_packet_len - sizeof(struct ip6_hdr);
    }

    // Step 3: Transport layer
    if (protocol == IPPROTO_TCP) {
        if (transport_len < sizeof(struct tcphdr)) return 0;
        const struct tcphdr* tcp = (const struct tcphdr*)transport;
        out->src_port  = ntohs(tcp->th_sport);
        out->dst_port  = ntohs(tcp->th_dport);
        strncpy(out->protocol, "TCP", 4);
        out->is_syn     = (tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK);
        out->is_syn_ack = (tcp->th_flags & TH_SYN) &&  (tcp->th_flags & TH_ACK);
    } else if (protocol == IPPROTO_UDP) {
        if (transport_len < sizeof(struct udphdr)) return 0;
        const struct udphdr* udp = (const struct udphdr*)transport;
        out->src_port = ntohs(udp->uh_sport);
        out->dst_port = ntohs(udp->uh_dport);
        strncpy(out->protocol, "UDP", 4);
    } else if (protocol == IPPROTO_ICMP) {
        strncpy(out->protocol, "ICMP", sizeof(out->protocol));
    } else if (protocol == IPPROTO_ICMPV6) {
        strncpy(out->protocol, "ICMPv6", sizeof(out->protocol));
    } else {
        strncpy(out->protocol, "???", sizeof(out->protocol));
    }
    return 1;
}

void format_endpoint(char* out, size_t size, const char* ip, uint16_t port) {
    if (strchr(ip, ':') != NULL)
        snprintf(out, size, "[%s]:%u", ip, (unsigned)port);
    else
        snprintf(out, size, "%s:%u", ip, (unsigned)port);
}
