#include "capture.h"
#include "decoder.h"
#include "tracker.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ConnectionTracker g_tracker;
static int g_packet_count = 0;
static LatencyTracker g_latency;

void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet);

pcap_t* open_capture(char* errbuf) {
    pcap_if_t* alldevs;

    // Find all available network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Could not find devices: %s\n", errbuf);
        return NULL;
    }

    // Use the first interface found
    if (alldevs == NULL) {
        fprintf(stderr, "No interfaces found\n");
        return NULL;
    }

    char dev[64];
    strncpy(dev, alldevs->name, 63);
    pcap_freealldevs(alldevs);  // free the list after copying the name

    printf("Listening on interface: %s\n", dev);

    pcap_t* handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return NULL;
    }
    return handle;
}

void start_capture(pcap_t* handle, int count) {
    pcap_loop(handle, count, packet_handler, NULL);
}

void init_tracker() {
    tracker_init(&g_tracker);
    latency_init(&g_latency);
}

void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet) {
    (void)args;
    PacketInfo info;

    if (!decode_packet(packet, header, &info)) return;

    if (strcmp(info.protocol, "TCP") == 0 ||
        strcmp(info.protocol, "UDP") == 0) {
        tracker_update(&g_tracker, &info);
        g_packet_count++;
    }

    if (strcmp(info.protocol, "TCP") == 0) {
        if (info.is_syn) {
            latency_record_syn(&g_latency, &info);
        } else if (info.is_syn_ack) {
            double rtt = latency_compute_rtt(&g_latency, &info);
            if (rtt >= 0) {
                printf("[RTT] %s:%d -> %s:%d = %.2f ms\n",
                       info.dst_ip, info.dst_port,
                       info.src_ip, info.src_port, rtt);
            }
        }
    }

    if (g_packet_count % 100 == 0 && g_packet_count > 0) {
        tracker_print(&g_tracker);
    }
}
