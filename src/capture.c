#include "capture.h"
#include "decoder.h"
#include "tracker.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

static ConnectionTracker g_tracker;
static pcap_t* g_handle = NULL;
static int g_linktype = DLT_EN10MB; 
static int g_is_live = 0;

// Counters for the final summary
static unsigned long g_total_seen    = 0;  // every packet the callback received
static unsigned long g_decoded       = 0;  // IPv4/IPv6 packets we could parse
static unsigned long g_flow_packets  = 0;  // TCP + UDP packets fed into the tracker

// Periodic reporting (-s N). Timed with packet timestamps
static int    g_report_interval = 0;   // seconds; 0 = off (only the final summary)
static time_t g_first_ts        = 0;   // timestamp (seconds) of the first packet
static time_t g_next_report     = 0;   // when the next snapshot is due

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

// Shared setup for every capture handle: check we can decode its link layer
static int prepare_handle(pcap_t* handle, const char* filter) {
    g_linktype = pcap_datalink(handle);
    if (!decoder_supports_linktype(g_linktype)) {
        fprintf(stderr, "Unsupported link-layer type: %s (%d)\n",
                pcap_datalink_val_to_name(g_linktype), g_linktype);
        return 0;
    }
    if (filter != NULL) {
    struct bpf_program prog;
    // Compile the filter expression into BPF bytecode, then attach it so the
    // kernel (or libpcap, for files) drops non-matching packets before our callback.
    if (pcap_compile(handle, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Bad filter '%s': %s\n", filter, pcap_geterr(handle));
        return 0;
    }
    if (pcap_setfilter(handle, &prog) == -1) {
        fprintf(stderr, "Could not apply filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&prog);
        return 0;
    }
    pcap_freecode(&prog);
    printf("Filter: %s\n", filter);
    }
    return 1;
}

pcap_t* open_capture(const char* device, const char* filter, char* errbuf) {
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
        if (device != NULL)
            fprintf(stderr, "Capture interface not found: %s (try -l to list interfaces)\n", device);
        else
            fprintf(stderr, "No capture interfaces found\n");
        pcap_freealldevs(alldevs);
        return NULL;
    }

    printf("Listening on interface: %s\n", selected->name);

    pcap_t* handle = pcap_create(selected->name, errbuf);
    pcap_freealldevs(alldevs);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return NULL;
    }
    pcap_set_snaplen(handle, 65536);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);
    pcap_set_immediate_mode(handle, 1);

    int status = pcap_activate(handle);
    if (status < 0) {
        fprintf(stderr, "Could not activate device: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    if (status > 0) {
        fprintf(stderr, "Warning: %s\n", pcap_geterr(handle));
    }
    if (!prepare_handle(handle, filter)) {
        pcap_close(handle);
        return NULL;
    }
    g_is_live = 1;
    return handle;
}

pcap_t* open_offline(const char* path, const char* filter, char* errbuf) {
    pcap_t* handle = pcap_open_offline(path, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open file: %s\n", errbuf);
        return NULL;
    }
    printf("Reading from file: %s\n", path);
    if (!prepare_handle(handle, filter)) {
        pcap_close(handle);
        return NULL;
    }
    g_is_live = 0;
    return handle;
}

static void on_sigint(int sig) {
    (void)sig;
    // Safe to call from a signal handler: pcap_breakloop only sets a flag that pcap_loop checks.
    if (g_handle != NULL) pcap_breakloop(g_handle);
}

void start_capture(pcap_t* handle, int count, int report_interval) {
    g_handle = handle;
    g_report_interval = report_interval;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int rc = pcap_loop(handle, count, packet_handler, NULL);
    if (rc == PCAP_ERROR) {
        fprintf(stderr, "Capture error: %s\n", pcap_geterr(handle));
    }

    g_handle = NULL;
}

static void print_counters(void) {
    printf("Packets received by callback : %lu\n", g_total_seen);
    printf("Decoded (IPv4/IPv6)          : %lu\n", g_decoded);
    printf("TCP/UDP packets tracked      : %lu\n", g_flow_packets);
}

// One periodic report: the connection table plus the counters so far.
static void report_snapshot(long elapsed_sec) {
    printf("\n--- Snapshot at +%lds ---\n", elapsed_sec);
    tracker_print(&g_tracker);
    print_counters();
    fflush(stdout);
}

void print_summary(pcap_t* handle) {
    tracker_print(&g_tracker);

    printf("\n=== Capture Summary ===\n");
    print_counters();

    // Kernel-level stats only exist for live captures. ps_drop counts packets
    // the OS dropped because our callback did not keep up (buffer full).
    if (g_is_live) {
        struct pcap_stat st;
        if (pcap_stats(handle, &st) == 0) {
            printf("Received by filter (kernel)  : %u\n", st.ps_recv);
            printf("Dropped (buffer full)        : %u\n", st.ps_drop);
            printf("Dropped by interface/driver  : %u\n", st.ps_ifdrop);
        }
    }
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

    g_total_seen++;
    if (!decode_packet(packet, header, g_linktype, &info)) return;
    g_decoded++;

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
                char client[56], server[56];
                format_endpoint(client, sizeof(client), info.dst_ip, info.dst_port);
                format_endpoint(server, sizeof(server), info.src_ip, info.src_port);
                printf("[RTT] %s -> %s : %.2f ms\n", client, server, rtt);
            }
        }
    }

    if (is_tcp || is_udp) {
        tracker_update(&g_tracker, &info);
        g_flow_packets++;
    }
    
    // Time-based snapshots (only with -s). The first packet starts the clock.
    if (g_report_interval > 0) {
        time_t now = header->ts.tv_sec;
        if (g_first_ts == 0) {
            g_first_ts = now;
            g_next_report = now + g_report_interval;
        } else if (now >= g_next_report) {
            report_snapshot((long)(now - g_first_ts));
            // Skip ahead past any quiet gap so we print once, not once per missed interval
            while (g_next_report <= now) g_next_report += g_report_interval;
        }
    }
}
