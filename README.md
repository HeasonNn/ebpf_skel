# ebpf_skel

**Generate vmlinux.h**
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux\vmlinux.h
```