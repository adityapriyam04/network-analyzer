#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include "capture.h"

static void usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [-i interface | -r file.pcap] [-f \"bpf filter\"] [-c count] [-s seconds] [-n top]\n"
        "       %s -l\n"
        "  -i  capture live on this interface (default: first available)\n"
        "  -r  read packets from a saved pcap file instead\n"
        "  -f  BPF filter expression, e.g. \"tcp port 443\"\n"
        "  -c  stop after this many packets (default: no limit)\n"
        "  -s  print a snapshot every N seconds of capture time (default: off)\n"
        "  -n  number of connections to list, ranked by bytes (default: 10)\n"
        "  -l  list capture interfaces and exit\n"
        "  -h  show this help message & exit\n",
        prog, prog);
}

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device = NULL;
    const char* file = NULL;
    const char* filter = NULL;
    int count = 0;
    int report_interval = 0;
    int top_n = 10;
    int opt;

    while((opt = getopt(argc, argv, "i:r:f:c:s:n:lh")) != -1) {
        switch (opt) {
            case 'i': device = optarg; break;
            case 'r': file = optarg; break;
            case 'f': filter = optarg; break;
            case 'c': count = atoi(optarg); break;
            case 's': report_interval = atoi(optarg); break;
            case 'n': top_n = atoi(optarg); break;
            case 'l': return list_capture_devices();
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
        }
    }
    if(optind < argc || (device != NULL && file != NULL) || count < 0 || report_interval < 0 || top_n < 1) {
        usage(argv[0]);
        return 1;
    }

    // Live capture: flush every line so `| tee` or `> capture.log` shows events as they happen
    if (file == NULL) setvbuf(stdout, NULL, _IOLBF, 0);
    
    pcap_t* handle = file != NULL ? open_offline(file, filter, errbuf): open_capture(device, filter, errbuf);
    if (handle == NULL) return 1;

    init_tracker();

        if (file != NULL)
        printf("Processing file...\n");
    else
        printf("Starting capture... (Ctrl+C to stop)\n");
    start_capture(handle, count, report_interval, top_n);
    print_summary(handle);

    pcap_close(handle);
    return 0;
}
