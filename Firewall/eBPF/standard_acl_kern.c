#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct ipv6_lpm_key {
        __u32 prefixlen;
        struct in6_addr data;
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, _Bool);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipv4_rules_trie SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, _Bool);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipv6_rules_trie SEC(".maps");

SEC("xdp")
int xdp_standard_acl(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Don't inspect packet if it's not an IPv4 or IPv6 packet */
    if (eth->h_proto == bpf_htons(ETH_P_IP) || eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
        _Bool *permitted_src;
        if (eth->h_proto == bpf_htons(ETH_P_IP))
        {
            struct iphdr *iph;
            __be32 src_ip;
            /* Get the IP header */
            iph = data + sizeof(struct ethhdr);

            /* Check if IP header is within bounds */
            if ((void *) iph + 1 > data_end)
            {
                return XDP_DROP;
            }
            /* Get the source IP */
            src_ip = iph->saddr;

            /* Get the forbidden source IP from the map */
            struct ipv4_lpm_key key = {
                    .prefixlen = 32,
                    .data = src_ip
            };
            permitted_src = (_Bool *)bpf_map_lookup_elem(&ipv4_rules_trie, &key);
        }
        else
        {
            struct ipv6hdr *ipv6h;
            struct in6_addr src_ip;
            /* Get the IP header */
            ipv6h = data + sizeof(struct ethhdr);

            /* Check if IP header is within bounds */
            if ((void *) ipv6h + 1 > data_end)
            {
                return XDP_DROP;
            }
            /* Get the source IP */
            src_ip = ipv6h->saddr;

            /* Get the forbidden source IP from the map */
            struct ipv6_lpm_key key = {
                    .prefixlen = 128,
                    .data = src_ip
            };
            permitted_src = (_Bool *)bpf_map_lookup_elem(&ipv6_rules_trie, &key);
        }

        /* Implicit "DENY ANY" at end of list*/
        return (permitted_src && *permitted_src) ? XDP_PASS : XDP_DROP;
    }

    /* Allow the packet if not IPv4/IPv6 packet */
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

// clang -O2 -g -Wall -target bpf -c standard_acl_kern.c -o standard_acl_kern.o