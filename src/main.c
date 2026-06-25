#include <stdio.h>
#include <pcap.h>
#include "capture.h"

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = open_capture(errbuf);
    if (handle == NULL) return 1;

    init_tracker();

    printf("Starting capture... (Ctrl+C to stop)\n");
    start_capture(handle, 0);

    pcap_close(handle);
    return 0;
}
