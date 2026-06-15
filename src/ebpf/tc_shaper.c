#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * This BPF map is dynamically populated by the Cyber Startup PyTorch Controller.
 * When the CT-GODE engine determines a Blast Radius Score exceeds the threshold,
 * the target IP is inserted here.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // Node ID (last octet of IP)
    __type(value, __u8); // Containment Redirection Flag
} compromised_ips SEC(".maps");

struct ctgode_weight_t {
    __u64 weight;
    __u64 timestamp;
    __u32 lambda_staleness;
};

/*
 * This BPF map holds the decentralized CT-GODE mathematical weights
 * pushed into the eBPF probe to enable swarm-based predictive consensus
 * natively via inter-node network packets.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ctgode_weight_t);
} ctgode_weights SEC(".maps");

static __always_inline void csum_replace4(__u16 *csum, __u32 from, __u32 to) {
    __u32 sum = *csum;
    sum = ~sum & 0xffff;
    sum += (~from & 0xffff);
    sum += (~from >> 16);
    sum += (to & 0xffff);
    sum += (to >> 16);
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    *csum = ~sum & 0xffff;
}

static __always_inline void csum_replace2(__u16 *csum, __u16 from, __u16 to) {
    __u32 sum = *csum;
    sum = ~sum & 0xffff;
    sum += (~from & 0xffff);
    sum += to;
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    *csum = ~sum & 0xffff;
}

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)(~csum);
}

static __always_inline __u16 calculate_ip_checksum(struct iphdr *ip, void *data_end) {
    ip->check = 0;
    __u32 csum = 0;
    __u16 *ptr = (__u16 *)ip;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        if ((void *)(&ptr[i] + 1) > data_end)
            break;
        csum += ptr[i];
    }
    return csum_fold(csum);
}

static __always_inline __u16 calculate_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, void *data_end) {
    tcp->check = 0;
    
    // 1. Sum the TCP Pseudo-Header
    __u32 csum = 0;
    __u16 *saddr_ptr = (__u16 *)&ip->saddr;
    __u16 *daddr_ptr = (__u16 *)&ip->daddr;
    
    csum += saddr_ptr[0];
    csum += saddr_ptr[1];
    csum += daddr_ptr[0];
    csum += daddr_ptr[1];
    
    csum += bpf_htons(IPPROTO_TCP);
    
    __u16 tcp_len = tcp->doff * 4;
    if (tcp_len < 20 || tcp_len > 60)
        return 0;
        
    csum += bpf_htons(tcp_len);
    
    // 2. Sum the actual TCP Header
    __u16 *ptr = (__u16 *)tcp;
    if ((void *)tcp + tcp_len > data_end)
        return 0;

    #pragma clang loop unroll(full)
    for (int i = 0; i < 30; i++) {
        if (i * 2 >= tcp_len)
            break;
        if ((void *)(&ptr[i] + 1) > data_end)
            break;
        csum += ptr[i];
    }
    
    return csum_fold(csum);
}


static __always_inline __u32 jenkins_hash(__u32 a, __u32 b, __u32 c, __u32 d) {
    __u32 hash = 0;
    hash += a; hash += (hash << 10); hash ^= (hash >> 6);
    hash += b; hash += (hash << 10); hash ^= (hash >> 6);
    hash += c; hash += (hash << 10); hash ^= (hash >> 6);
    hash += d; hash += (hash << 10); hash ^= (hash >> 6);
    hash += (hash << 3); hash ^= (hash >> 11); hash += (hash << 15);
    return hash;
}

SEC("xdp")
int semantic_shaper(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 dst_ip = ip->daddr;
    __u32 node_id = (bpf_ntohl(dst_ip) & 0xFF);
// Check if destination IP is marked as compromised by the Neural Engine
__u8 *is_compromised = bpf_map_lookup_elem(&compromised_ips, &node_id);
struct ctgode_weight_t *swarm_data = bpf_map_lookup_elem(&ctgode_weights, &node_id);
    
    // Native Swarm BRS verification (distributing ODE calculation to the eBPF probe natively)
    if (is_compromised && *is_compromised == 1 && swarm_data) {
        __u64 swarm_weight = swarm_data->weight;
        // eBPF native BRS math: if the distributed swarm weight > threshold
        if (swarm_weight > 50) {
        // Implement e^{-\lambda \Delta t} exponential time-decay logic (Claim 7)
        // utilizing bitwise shifting for stateful true exponential decay W * 2^(-t)
        __u64 current_time = bpf_ktime_get_ns();
        __u64 delta_t_sec = (current_time - swarm_data->timestamp) / 1000000000ULL;
        __u64 decayed_weight = swarm_weight >> (delta_t_sec * swarm_data->lambda_staleness);
        if (decayed_weight < 25) {
            // Decay threshold reached, drop packet instead of shaping
            return XDP_DROP;
        }
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;

            // Semantic Shaping Logic: Forge a SYN-ACK for incoming SYN
            // This actively deceives the unauthorized actor by pretending the port is open (Containment Node)
            if (tcp->syn && !tcp->ack) {
                // Swap MAC addresses
                unsigned char tmp_mac[ETH_ALEN];
                __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                // Capture old values for TCP checksum update
                __u32 old_seq = tcp->seq;
                __u32 old_ack_seq = tcp->ack_seq;
                __u16 old_flags = ((__u16 *)tcp)[6];

                // Swap IP addresses
                __u32 tmp_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = tmp_ip;

                // Swap TCP ports
                __u16 tmp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = tmp_port;

                // Set SYN-ACK flags
                tcp->ack = 1;
                tcp->ack_seq = bpf_htonl(bpf_ntohl(old_seq) + 1);
                
                // POLYMORPHIC_INJECTION_POINT
                
                tcp->seq = bpf_htonl(ip->saddr ^ ip->daddr ^ (__u32)decayed_weight ^ (__u32)(current_time & 0xFFFFFFFF)); // Synthetic containment node sequence number utilizing continuous time decay

                // Recalculate IP checksum from scratch
                ip->check = 0;
                __u32 ip_csum = 0;
                __u16 *ip_u16 = (__u16 *)ip;
                #pragma clang loop unroll(full)
                for (int i = 0; i < 10; i++) {
                    ip_csum += ip_u16[i];
                }
                while (ip_csum >> 16) {
                    ip_csum = (ip_csum & 0xffff) + (ip_csum >> 16);
                }
                ip->check = ~ip_csum;

                // Update TCP checksum incrementally
                csum_replace4(&tcp->check, old_seq, tcp->seq);
                csum_replace4(&tcp->check, old_ack_seq, tcp->ack_seq);
                csum_replace2(&tcp->check, old_flags, ((__u16 *)tcp)[6]);
                
                // Return TX to send the forged response back out the same interface
                return XDP_TX;
            }
            
            // If not a SYN, just drop to isolate
            return XDP_DROP;
        }
        } // End of swarm_weight > 500 check
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
