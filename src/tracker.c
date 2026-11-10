#include "tracker.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

static unsigned int hash_key(const char* key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) + (unsigned char)(*key);
        key++;
    }
    return hash % MAX_CONNECTIONS;
}

void tracker_init(ConnectionTracker* t) {
    memset(t, 0, sizeof(ConnectionTracker));
}

void tracker_update(ConnectionTracker* t, const PacketInfo* pkt) {
    char key[128];
    snprintf(key, sizeof(key), "%s:%d->%s:%d",
             pkt->src_ip, pkt->src_port,
             pkt->dst_ip, pkt->dst_port);

    unsigned int idx = hash_key(key);
    unsigned int start = idx;

    do {
        Connection* slot = &t->slots[idx];

        if (!slot->active) {
            snprintf(slot->key, sizeof(slot->key), "%s", key);
            snprintf(slot->src_ip, sizeof(slot->src_ip), "%s", pkt->src_ip);
            snprintf(slot->dst_ip, sizeof(slot->dst_ip), "%s", pkt->dst_ip);
            slot->src_port     = pkt->src_port;
            slot->dst_port     = pkt->dst_port;
            slot->packet_count = 1;
            slot->bytes_total  = pkt->length;
            slot->first_seen   = pkt->timestamp;
            slot->last_seen    = pkt->timestamp;
            slot->active       = 1;
            t->count++;
            return;
        }

        if (strcmp(slot->key, key) == 0) {
            slot->packet_count++;
            slot->bytes_total += pkt->length;
            slot->last_seen    = pkt->timestamp;
            return;
        }

        idx = (idx + 1) % MAX_CONNECTIONS;

    } while (idx != start);

    fprintf(stderr, "Connection table full!\n");
}

void tracker_print(const ConnectionTracker* t) {
    printf("\n=== Active Connections (%d) ===\n", t->count);
    printf("%-45s %8s %12s\n", "Connection", "Packets", "Bytes");
    printf("%-45s %8s %12s\n", "----------", "-------", "-----");

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (t->slots[i].active) {
                printf("%-45s %8" PRIu64 " %12" PRIu64 "\n",
                   t->slots[i].key,
                   t->slots[i].packet_count,
                   t->slots[i].bytes_total);
        }
    }
}
