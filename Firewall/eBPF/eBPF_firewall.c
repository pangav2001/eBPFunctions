#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_endian.h>

#define IPV6_BYTES 16
struct IPv4Rule {
    __be32 src_ip;
    __be32 src_ip_wildcard_mask;
    __be32 dst_ip;
    __be32 dst_ip_wildcard_mask;
    __be16 min_src_port;
    __be16 max_src_port;
    __be16 min_dst_port;
    __be16 max_dst_port;
    __u8 protocol;
    _Bool allow;
};

struct IPv4Packet {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 protocol;
    __be16 src_port;
    __be16 dst_port;
};

struct IPv4Lookup {
    struct IPv4Packet *ipv4_pkt;
    _Bool allow;
};

struct IPv6Rule {
    struct in6_addr src_ip;
    struct in6_addr src_ip_wildcard_mask;
    struct in6_addr dst_ip;
    struct in6_addr dst_ip_wildcard_mask;
    __be16 min_src_port;
    __be16 max_src_port;
    __be16 min_dst_port;
    __be16 max_dst_port;
    __u8 protocol;
    _Bool allow;
};

struct IPv6Packet {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __u8 protocol;
    __be16 src_port;
    __be16 dst_port;
};

struct IPv6Lookup {
    struct IPv6Packet *ipv6_pkt;
    _Bool allow;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct IPv4Rule);
    __uint(max_entries, 500);
} ipv4_rules SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct IPv6Rule);
    __uint(max_entries, 100);
} ipv6_rules SEC(".maps");

static __u32 check_ipv4_rule(void *map, __u32 *key, struct IPv4Rule *val,
                struct IPv4Lookup *data) {
                    val = bpf_map_lookup_elem(map, key);
                    if (val
                    && (data->ipv4_pkt->src_ip | val->src_ip_wildcard_mask) == (val->src_ip | val->src_ip_wildcard_mask) 
                    && (data->ipv4_pkt->dst_ip | val->dst_ip_wildcard_mask) == (val->dst_ip | val->dst_ip_wildcard_mask)
                    && (val->protocol == 255 || data->ipv4_pkt->protocol == val->protocol)
                    && (data->ipv4_pkt->src_port >= val->min_src_port && data->ipv4_pkt->src_port <= val->max_src_port)
                    && (data->ipv4_pkt->dst_port >= val->min_dst_port && data->ipv4_pkt->dst_port <= val->max_dst_port)) {
                        data->allow = val->allow;
                        return 1;
                    }
                    return 0;
                }

static __u32 check_ipv6_rule(void *map, __u32 *key, struct IPv6Rule *val,
                struct IPv6Lookup *data) {
                    val = bpf_map_lookup_elem(map, key);
                    if (val
                    && (val->protocol == 255 || data->ipv6_pkt->protocol == val->protocol)
                    && (data->ipv6_pkt->src_port >= val->min_src_port && data->ipv6_pkt->src_port <= val->max_src_port)
                    && (data->ipv6_pkt->dst_port >= val->min_dst_port && data->ipv6_pkt->dst_port <= val->max_dst_port)) {
                        _Bool match = 1;
                        for(__u32 i = 0; i < IPV6_BYTES; i++)
                        {
                            if (((data->ipv6_pkt->src_ip.in6_u.u6_addr8[i] | val->src_ip_wildcard_mask.in6_u.u6_addr8[i]) 
                            != (val->src_ip.in6_u.u6_addr8[i] | val->src_ip_wildcard_mask.in6_u.u6_addr8[i]))
                            || ((data->ipv6_pkt->dst_ip.in6_u.u6_addr8[i] | val->dst_ip_wildcard_mask.in6_u.u6_addr8[i])
                            != (val->dst_ip.in6_u.u6_addr8[i] | val->dst_ip_wildcard_mask.in6_u.u6_addr8[i]))) {
                                match = 0;
                                break;
                            }
                        }
                        if (match) {
                            data->allow = val->allow;
                            return 1;
                        }
                    }
                    return 0;
                }

// 90:e2:ba:f7:32:69
unsigned char my_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x32, 0x69};
// 90:E2:BA:F7:30:1D
unsigned char source_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x30, 0x1d};
// 90:E2:BA:F7:31:CD
unsigned char target_mac[] = {0x90, 0xe2, 0xba, 0xf7, 0x31, 0xcd};

static __always_inline int _strcmp (const unsigned char *buf1, const unsigned char *buf2, unsigned long size) {
    unsigned char c1, c2;
    for (unsigned long i = 0; i < size; i++)
    {
        c1 = *buf1++;
        c2 = *buf2++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1) break;
    }
    return 0;
} 
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_DROP;
    }
    _Bool permitted = 0;
    /* Don't inspect packet if it's not an IPv4 packet or IPv6 packet */
    if (eth->h_proto == bpf_htons(ETH_P_IP))
    {
        struct IPv4Packet ipv4_pkt = {
            .src_port = 0,
            .dst_port = 0
        };
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end)
        {
            return XDP_DROP;
        }
        /* Get the source and destination IPs */
        ipv4_pkt.src_ip = bpf_ntohl(iph->saddr);
        ipv4_pkt.dst_ip = bpf_ntohl(iph->daddr);
        /* Get the protocol */
        ipv4_pkt.protocol = iph->protocol;

        if (ipv4_pkt.protocol == IPPROTO_TCP || ipv4_pkt.protocol == IPPROTO_UDP)
        {
            /* Get the TCP or UDP header */
            if (ipv4_pkt.protocol == IPPROTO_TCP)
            {
                struct tcphdr *tcph = (void *) iph + sizeof(struct iphdr);
                if ((void *)(tcph + 1) > data_end)
                {
                    return XDP_DROP;
                }
                /* Get the source and destination ports */
                ipv4_pkt.src_port = bpf_ntohs(tcph->source);
                ipv4_pkt.dst_port = bpf_ntohs(tcph->dest);
            }
            else
            {
                struct udphdr *udph = (void *) iph + sizeof(struct iphdr);
                if ((void *)(udph + 1) > data_end)
                {
                    return XDP_DROP;
                }
                /* Get the source and destination ports */
                ipv4_pkt.src_port = bpf_ntohs(udph->source);
                ipv4_pkt.dst_port = bpf_ntohs(udph->dest);
            }
        }
        struct IPv4Lookup ipv4_lookup = {
            .ipv4_pkt = &ipv4_pkt
        };
        struct IPv4Rule *ipv4_rule = (void *)0;
        __u32 key;
        for (__u32 i = 0; i < 500; i++)
        {
            key = i;
            if(check_ipv4_rule(&ipv4_rules, &key, ipv4_rule, &ipv4_lookup))
                {
                    permitted = ipv4_lookup.allow;
                    break;
                }
        }
    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct IPv6Packet ipv6_pkt = {
            .src_port = 0,
            .dst_port = 0
        };
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end)
        {
            return XDP_DROP;
        }
        /* Get the source and destination IPs */
        ipv6_pkt.src_ip = ip6h->saddr;
        ipv6_pkt.dst_ip = ip6h->daddr;
        /* Get the protocol */
        ipv6_pkt.protocol = ip6h->nexthdr;

        if (ipv6_pkt.protocol == IPPROTO_TCP || ipv6_pkt.protocol == IPPROTO_UDP)
        {
            /* Get the TCP or UDP header */
            if (ipv6_pkt.protocol == IPPROTO_TCP)
            {
                struct tcphdr *tcph = (void *) ip6h + sizeof(struct ipv6hdr);
                if ((void *)(tcph + 1) > data_end)
                {
                    return XDP_DROP;
                }
                /* Get the source and destination ports */
                ipv6_pkt.src_port = bpf_ntohs(tcph->source);
                ipv6_pkt.dst_port = bpf_ntohs(tcph->dest);
            }
            else
            {
                struct udphdr *udph = (void *) ip6h + sizeof(struct ipv6hdr);
                if ((void *)(udph + 1) > data_end)
                {
                    return XDP_DROP;
                }
                /* Get the source and destination ports */
                ipv6_pkt.src_port = bpf_ntohs(udph->source);
                ipv6_pkt.dst_port = bpf_ntohs(udph->dest);
            }
        }
        struct IPv6Lookup ipv6_lookup = {
            .ipv6_pkt = &ipv6_pkt
        };
        struct IPv6Rule *ipv6_rule = (void *)0;
        __u32 key;
        for (__u32 i = 0; i < 10; i++)
        {
            key = i;
            if(check_ipv6_rule(&ipv6_rules, &key, ipv6_rule, &ipv6_lookup))
                {
                    permitted = ipv6_lookup.allow;
                    break;
                }
        }
    }
    else {
        /* Allow the packet */
        return XDP_PASS;
    }
    if (permitted) {
        /* Check that source MAC is that of MoonGen sender
           and destination MAC is that of the NIC running the XDP prog*/
            if (!(_strcmp(eth->h_source, source_mac, ETH_ALEN) 
                || _strcmp(eth->h_dest, my_mac, ETH_ALEN))) {
                /* Swap MAC addresses as appropriate */
                __builtin_memcpy(eth->h_source, my_mac, ETH_ALEN);
                __builtin_memcpy(eth->h_dest, target_mac, ETH_ALEN);
                /* Send packet to new destination */
                return XDP_TX;
            }
    }
    else {
        /* Implicit "DENY" rule at the end */
        return XDP_DROP;
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

// clang -O2 -g -Wall -target bpf -c eBPF_firewall.c -o eBPF_firewall.o