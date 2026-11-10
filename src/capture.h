#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Opens a live capture session on the selected interface, or the first available one.
pcap_t* open_capture(const char* device, char* errbuf);

// Prints the available capture interfaces.
int list_capture_devices(void);

// Starts the capture loop — calls packet_handler for each packet
// count = 0 means capture indefinitely
void start_capture(pcap_t* handle, int count);

// Prints the connection table plus packet/drop counters.
void print_summary(pcap_t* handle);

// Called once from main() to initialize tracker and latency modules
void init_tracker();

#endif
