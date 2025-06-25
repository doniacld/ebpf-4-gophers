//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// Map from source IP (u32) to packet count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);       // Source IP
    __type(value, __u64);     // Packet count
    __uint(max_entries, 1024);
} pkt_count SEC(".maps");

SEC("xdp")
int count_packets_by_src(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Try to find existing counter for src_ip
    __u64 *value = bpf_map_lookup_elem(&pkt_count, &src_ip);
    if (value) {
        (*value)++;
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&pkt_count, &src_ip, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
