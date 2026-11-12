#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Prints the available capture interfaces.
int list_capture_devices(void);

// Opens a live capture on the given interface (NULL = first available).
// filter is an optional BPF expression, e.g. "tcp port 443" (NULL = none).
pcap_t* open_capture(const char* device, const char* filter, char* errbuf);

// Opens a saved .pcap file instead of a live interface.
pcap_t* open_offline(const char* path, const char* filter, char* errbuf);

// Runs the capture loop until count packets, end of file, or Ctrl+C.
// count = 0 means no packet limit.
// report_interval = print a snapshot every N seconds of capture time (0 = off).
// top_n = how many connection the table shows (ranked by bytes, descending).
void start_capture(pcap_t* handle, int count, int report_interval, int top_n);

// Prints the connection table plus packet/drop counters.
void print_summary(pcap_t* handle);

// Called once from main() to initialize tracker and latency modules
void init_tracker();

#endif
