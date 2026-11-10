#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "capture.h"

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        return list_capture_devices();
    }
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        fprintf(stderr, "Usage: %s [interface | --list]\n", argv[0]);
        return argc == 2 ? 0 : 1;
    }

    pcap_t* handle = open_capture(argc == 2 ? argv[1] : NULL, errbuf);
    if (handle == NULL) return 1;

    init_tracker();

    printf("Starting capture... (Ctrl+C to stop)\n");
    start_capture(handle, 0);
    print_summary(handle);

    pcap_close(handle);
    return 0;
}
