#include "capture.h"
#include "decoder.h"
#include "tracker.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRINT_EVERY_N_FLOW_PACKETS 100

static ConnectionTracker g_tracker;
static unsigned int g_flow_packets = 0;
static LatencyTracker g_latency;

void packet_handler(u_char* args,
                    const struct pcap_pkthdr* header,
                    const u_char* packet);

int list_capture_devices(void) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Could not find devices: %s\n", errbuf);
        return 1;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No interfaces found\n");
        return 1;
    }

    for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%s%s%s\n", dev->name,
               dev->description != NULL ? " - " : "",
               dev->description != NULL ? dev->description : "");
    }

    pcap_freealldevs(alldevs);
    return 0;
}

pcap_t* open_capture(const char* device, char* errbuf) {
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Could not find devices: %s\n", errbuf);
        return NULL;
    }

    pcap_if_t* selected = alldevs;
    if (device != NULL) {
        while (selected != NULL && strcmp(selected->name, device) != 0) {
            selected = selected->next;
        }
    }

    if (selected == NULL) {
        fprintf(stderr, "Capture interface not found: %s\n", device);
        pcap_freealldevs(alldevs);
        return NULL;
    }

    printf("Listening on interface: %s\n", selected->name);

    pcap_t* handle = pcap_open_live(selected->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);
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
    
    int is_tcp = strcmp(info.protocol, "TCP") == 0;
    int is_udp = strcmp(info.protocol, "UDP") == 0;


    if (strcmp(info.protocol, "ICMP") == 0 ||
        strcmp(info.protocol, "ICMPv6") == 0) {
        printf("[%s] %s -> %s (%u bytes)\n",
               info.protocol, info.src_ip, info.dst_ip, info.length);
        fflush(stdout);
    }

    if (is_tcp) {
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

    if (is_tcp || is_udp) {
        tracker_update(&g_tracker, &info);
        g_flow_packets++;
    }
    if (g_flow_packets % PRINT_EVERY_N_FLOW_PACKETS == 0 ) {
        tracker_print(&g_tracker);
    }
}
