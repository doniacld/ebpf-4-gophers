//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/byteorder/little_endian.h>

// Blocked destination IP address (e.g., 192.168.0.1)
//#define BLOCKED_IP 0xC0A80001 // 192.168.0.1 in hex
#define BLOCKED_IP 0x7f000001 // 127.0.0.1 in hex


// This function checks if the destination IP is blocked
static inline int isBlockedIP(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip;

    // Ensure there is enough data for the Ethernet and IP headers
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;  // Not enough data for IP header
    }

    ip = (struct iphdr *)(eth + 1);

    // Ensure there is enough data for the IP header
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;  // Not enough data for IP header fields
    }

    // Check if the destination IP matches the blocked IP
    if (ip->daddr == __constant_htonl(BLOCKED_IP)) {
        return XDP_DROP;  // Blocked IP found
    }

    return XDP_PASS;  // Not blocked
}

// Main XDP program function
SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    char msg[] = "Hello, World!";
    bpf_trace_printk(msg, sizeof(msg));  // Print to trace pipe
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if the packet's destination IP is blocked
    if (isBlockedIP(data, data_end)) {
        char msg[] = "Got ping packet";
        bpf_trace_printk(msg, sizeof(msg));  // Print to trace pipe
        return XDP_DROP;
    }

    return XDP_PASS;  // Allow the packet to pass
}

// License declaration
char _license[] SEC("license") = "GPL";
