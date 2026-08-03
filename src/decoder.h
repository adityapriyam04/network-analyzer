#ifndef DECODER_H
#define DECODER_H

#include <stdint.h>
#include <sys/time.h>
#include <pcap.h>

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[4];
    uint32_t length;
    struct timeval timestamp;
    int is_syn;
    int is_syn_ack;
} PacketInfo;

// Returns 1 on success, 0 if not an IP packet
int decode_packet(const u_char* packet,
                  const struct pcap_pkthdr* header,
                  PacketInfo* out);

#endif
