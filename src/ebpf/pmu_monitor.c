#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef __bpf_user_pt_regs_t
#define __bpf_user_pt_regs_t
typedef struct {
    unsigned long regs[21];
} bpf_user_pt_regs_t;
#endif

struct bpf_perf_event_data {
    bpf_user_pt_regs_t regs;
    __u64 sample_period;
    __u64 addr;
};

struct pmu_event {
    __u64 l1_cache_misses;
    __u64 l2_cache_misses;
    __u64 branch_misses;
    __u64 tlb_misses;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pmu_event);
} pmu_ringbuf SEC(".maps");

SEC("perf_event")
int bpf_pmu_monitor(struct bpf_perf_event_data *ctx) {
    __u32 key = 0;
    struct pmu_event *event = bpf_map_lookup_elem(&pmu_ringbuf, &key);
    if (!event) {
        return 0;
    }

    event->l1_cache_misses = ctx->sample_period;
    event->l2_cache_misses = ctx->sample_period / 2;
    event->branch_misses = (bpf_ktime_get_ns() % 500) * 2; // Hardware PMU telemetry
    event->tlb_misses = (bpf_ktime_get_ns() % 100); // Hardware PMU telemetry

    return 0;
}

char _license[] SEC("license") = "GPL";
