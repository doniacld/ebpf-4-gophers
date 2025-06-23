//go:build ignore

#include <linux/bpf.h>           // BPF header for definitions.
#include <bpf/bpf_helpers.h>      // BPF helper functions.

SEC("tracepoint/syscalls/sys_enter_openat")  // Attach to sys_enter_openat tracepoint.
int trace_openat(void *ctx) {
    bpf_printk("File opening...");  // Log message.

    return 0;  // Return success.
}

char LICENSE[] SEC("license") = "GPL";  // GPL license.
