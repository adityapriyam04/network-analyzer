#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Opens a live capture session on the default network interface
pcap_t* open_capture(char* errbuf);

// Starts the capture loop — calls packet_handler for each packet
// count = 0 means capture indefinitely
void start_capture(pcap_t* handle, int count);

// Called once from main() to initialize tracker and latency modules
void init_tracker();

#endif
