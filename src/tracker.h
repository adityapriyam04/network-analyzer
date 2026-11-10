#ifndef TRACKER_H
#define TRACKER_H

#include <stdint.h>
#include <sys/time.h>
#include "decoder.h"

#define MAX_CONNECTIONS 4096

typedef struct {
    char key[128];
    char src_ip[46];
    char dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t packet_count;
    uint64_t bytes_total;
    struct timeval first_seen;
    struct timeval last_seen;
    int active;
} Connection;

typedef struct {
    Connection slots[MAX_CONNECTIONS];
    int count;
} ConnectionTracker;

void tracker_init(ConnectionTracker* t);
void tracker_update(ConnectionTracker* t, const PacketInfo* pkt);
void tracker_print(const ConnectionTracker* t);

#endif
