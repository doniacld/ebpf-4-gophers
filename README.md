# Learn eBPF for Gophers 

This repo accompanies my talk to FOSDEM 2025: "An intro to eBPF with Go:
The foundation of modern Kubernetes". You can watch the talk here [TBC].

## Run the example code

I use a VM [Lima](https://github.com/lima-vm/lima), there is a [config file](lima.yaml) with all the needed dependencies.
The kernel version of the VM when running these example is xx.xx.
All these examples have been tested on an Ubuntu 22.04 distribution using a 5.15 kernel.

## Lima VM
```shell
limactl start lima.yaml --name=learn-ebpf
limactl shell learn-ebpf
```

## Examples

It includes all the demo realised during the talk.
- Tracing example: [Open file tracer](./01-openfile)
- Monitoring examples: [Packet counter](./02-00-counter) and [Packet counter with source IPs](./02-01-counter-ips)
- Networking/Security example: [Drop packets](./03-xdpdrop)

## View eBPF trace output

A couple of ways to see the output from the kernel's trace pipe where eBPF tracing gets written:
```shell
cat /sys/kernel/debug/tracing/trace_pipe
```

```shell
bpftool prog tracelog
```

## Resources to go further

- eBPF website: https://ebpf.io
- eBPF docs for developers - https://docs.ebpf.io/
- eBPF and Go with [cilium/ebpf](https://github.com/cilium/ebpf) library - https://ebpf-go.dev/
- Lab Getting Started with eBPF: https://isovalent.com/labs/ebpf-getting-started/
- [Learning eBPF Book](https://isovalent.com/books/learning-ebpf/), O'Reilly by Liz Rice

## Troubleshooting

<details>
<summary>Operation not permitted</summary>

```shell
$ go run .
2025/06/24 10:34:22 Removing memlockfailed to set memlock rlimit: operation not permitted
```

You need priviledges, run your program with `sudo`.
```shell
sudo go run .
```
</details>
