#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

// https://docs.kernel.org/bpf/map_array.html
// https://docs.kernel.org/bpf/maps.html
// https://github.com/libbpf/libbpf/wiki/Libbpf:-the-road-to-v1.0#drop-support-for-legacy-bpf-map-declaration-syntax

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, _Bool);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 10);
} lpm_trie SEC(".maps");

SEC("xdp")
int xdp_lpm_test(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __be32 src_ip;
    __be32 dst_ip;
    _Bool *forbidden_src;

    /* Get the IP header */
    iph = data + sizeof(*eth);

    /* Check if IP header is within bounds */
    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }
    /* Don't inspect packet if it's not an IPv4 packet */
    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        /* Get the source and destination IPs */
        src_ip = iph->saddr;
        dst_ip = iph->daddr;

        // One of the two is 0 when pinging locally
        /* Check if the destination IP is within bounds */
        if (src_ip == 0 || dst_ip == 0)
        {
            return XDP_DROP;
        }

        /* Get the forbidden source IP from the map */
        struct ipv4_lpm_key key = {
                .prefixlen = 32,
                .data = src_ip
        };
        forbidden_src = (_Bool *)bpf_map_lookup_elem(&lpm_trie, &key);
        if (forbidden_src && *forbidden_src)
        {
            return XDP_DROP;
        }
    }

    /* Allow the packet */
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

// clang -O2 -g -Wall -target bpf -c lpm_trie_test.c -o lpm_trie_test.o