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
    char src[56], dst[56];
    format_endpoint(src, sizeof(src), pkt->src_ip, pkt->src_port);
    format_endpoint(dst, sizeof(dst), pkt->dst_ip, pkt->dst_port);
    char key[128];
    snprintf(key, sizeof(key), "%s -> %s", src, dst);

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

    // Warn once, not on every packet
    static int warned = 0;
    if (!warned) {
        fprintf(stderr, "Connection table full! New connections are not being tracked.\n");
        warned = 1;
    }
}

void tracker_print_top(const ConnectionTracker* t, int top_n) {
    if (top_n < 1) top_n = 1;
    if (top_n > MAX_CONNECTIONS) top_n = MAX_CONNECTIONS;

    // One pass over the table, keeping a small sorted list of the best top_n.
    // Cost is about the same as one scan of the table; no full sort needed.
    const Connection* top[MAX_CONNECTIONS];
    int shown = 0;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        const Connection* c = &t->slots[i];
        if (!c->active) continue;

        int pos;
        if (shown < top_n) {
            pos = shown++;
        } else if (c->bytes_total > top[top_n - 1]->bytes_total) {
            pos = top_n - 1;          // replace the current smallest
        } else {
            continue;
        }
        while (pos > 0 && top[pos - 1]->bytes_total < c->bytes_total) {
            top[pos] = top[pos - 1];  // shift smaller entries down
            pos--;
        }
        top[pos] = c;
    }

    // Size the first column to the longest key we are about to print.
    int width = (int)strlen("Connection");
    for (int i = 0; i < shown; i++) {
        int len = (int)strlen(top[i]->key);
        if (len > width) width = len;
    }

    printf("\n=== Top %d of %d connections by bytes ===\n", shown, t->count);
    printf("%-*s %8s %12s\n", width, "Connection", "Packets", "Bytes");
    printf("%-*s %8s %12s\n", width, "----------", "-------", "-----");
    for (int i = 0; i < shown; i++) {
        printf("%-*s %8" PRIu64 " %12" PRIu64 "\n", width, top[i]->key,
               top[i]->packet_count, top[i]->bytes_total);
    }
}
