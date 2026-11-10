#include "metrics.h"
#include <stdio.h>
#include <string.h>

void latency_init(LatencyTracker* lt) {
    memset(lt, 0, sizeof(LatencyTracker));
}

void latency_record_syn(LatencyTracker* lt, const PacketInfo* pkt) {
    char key[128];
    snprintf(key, sizeof(key), "%s:%d->%s:%d",
             pkt->src_ip, pkt->src_port,
             pkt->dst_ip, pkt->dst_port);

    for (int i = 0; i < MAX_PENDING_SYN; i++) {
        if (!lt->entries[i].active) {
            snprintf(lt->entries[i].key, sizeof(lt->entries[i].key), "%s", key);
            lt->entries[i].ts     = pkt->timestamp;
            lt->entries[i].active = 1;
            return;
        }
    }
}

double latency_compute_rtt(LatencyTracker* lt, const PacketInfo* pkt) {
    char key[128];
    // SYN-ACK is reversed — server replies back
    snprintf(key, sizeof(key), "%s:%d->%s:%d",
             pkt->dst_ip, pkt->dst_port,
             pkt->src_ip, pkt->src_port);

    for (int i = 0; i < MAX_PENDING_SYN; i++) {
        if (lt->entries[i].active &&
            strcmp(lt->entries[i].key, key) == 0) {

            struct timeval syn_ts = lt->entries[i].ts;
            lt->entries[i].active = 0;

            double rtt =
                (pkt->timestamp.tv_sec  - syn_ts.tv_sec)  * 1000.0 +
                (pkt->timestamp.tv_usec - syn_ts.tv_usec) / 1000.0;

            return rtt;
        }
    }
    return -1.0;
}
