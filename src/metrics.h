#ifndef METRICS_H
#define METRICS_H

#include <sys/time.h>
#include "decoder.h"

#define MAX_PENDING_SYN 1024

typedef struct {
    char key[64];
    struct timeval ts;
    int active;
} SynEntry;

typedef struct {
    SynEntry entries[MAX_PENDING_SYN];
} LatencyTracker;

void latency_init(LatencyTracker* lt);
void latency_record_syn(LatencyTracker* lt, const PacketInfo* pkt);
double latency_compute_rtt(LatencyTracker* lt, const PacketInfo* pkt);

#endif
