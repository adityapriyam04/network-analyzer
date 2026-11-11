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
void start_capture(pcap_t* handle, int count);

// Prints the connection table plus packet/drop counters.
void print_summary(pcap_t* handle);

// Called once from main() to initialize tracker and latency modules
void init_tracker();

#endif
