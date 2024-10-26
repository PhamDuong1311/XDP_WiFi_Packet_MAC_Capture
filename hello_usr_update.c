#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

struct key {
    __u8 address[6];
};
struct value {
    __u64 timesAppearReceiver;
    __u64 timesAppearSource;
    __u64 timesAppearMinor;
};

int parse_mac_address(const char *mac_str, __u8 *mac) {
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ? 0 : -1;
}

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp_map_count1"); 
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    struct key search_key;
    struct value val;
    char input[18];

    while (1) {
        printf("Enter MAC address (or type 'exit' to quit): ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("Error reading input.\n");
            continue;
        }

        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "exit") == 0) {
            break;
        }

        if (parse_mac_address(input, search_key.address) < 0) {
            printf("Invalid MAC address format.\n");
            continue;
        }

        if (bpf_map_lookup_elem(map_fd, &search_key, &val) == 0) {
            printf("Address %02x:%02x:%02x:%02x:%02x:%02x\n",
                   search_key.address[0], search_key.address[1], search_key.address[2],
                   search_key.address[3], search_key.address[4], search_key.address[5]);
            printf("Times as Receiver: %llu\n", val.timesAppearReceiver);
            printf("Times as Source: %llu\n", val.timesAppearSource);
            printf("Times as Minor: %llu\n", val.timesAppearMinor);
        } else {
            printf("MAC address not found in map.\n");
        }

        printf("\n");
    }

    close(map_fd);
    return 0;
}
