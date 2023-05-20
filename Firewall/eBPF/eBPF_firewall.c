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

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct IPv4Rule);
    __uint(max_entries, 100);
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
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_ABORTED;
    }
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
            return XDP_ABORTED;
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
                    return XDP_ABORTED;
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
                    return XDP_ABORTED;
                }
                /* Get the source and destination ports */
                ipv4_pkt.src_port = bpf_ntohs(udph->source);
                ipv4_pkt.dst_port = bpf_ntohs(udph->dest);
            }
        }
        struct IPv4Lookup ipv4_lookup = {
            .ipv4_pkt = &ipv4_pkt
        };
        struct IPv4Rule *ipv4_rule = NULL;
        __u32 key;
        for (__u32 i = 0; i < 100; i++)
        {
            key = i;
            if(check_ipv4_rule(&ipv4_rules, &key, ipv4_rule, &ipv4_lookup))
                return ipv4_lookup.allow ? XDP_PASS : XDP_DROP;
        }

        // bpf_for_each_map_elem(&ipv4_rules, &check_ipv4_rule, &ipv4_lookup, 0);
        // return ipv4_lookup.allow ? XDP_PASS : XDP_DROP;

    }
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // TODO
    }

    /* Allow the packet */
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

// clang -O2 -g -Wall -target bpf -c eBPF_firewall.c -o eBPF_firewall.o
// struct IPv4Rule ipv4_rulee;
// if (val){
//     ipv4_rulee.src_ip = data->ipv4_pkt->src_ip;
//     ipv4_rulee.src_ip_wildcard_mask = data->ipv4_pkt->src_ip | val->src_ip_wildcard_mask;
//     ipv4_rulee.dst_ip = data->ipv4_pkt->dst_ip;
//     ipv4_rulee.dst_ip_wildcard_mask = data->ipv4_pkt->dst_ip | val->dst_ip_wildcard_mask;
//     ipv4_rulee.max_src_port = val->min_src_port;
//     ipv4_rulee.max_dst_port = val->min_dst_port;
//     ipv4_rulee.protocol = data->ipv4_pkt->protocol;
//     ipv4_rulee.min_src_port = data->ipv4_pkt->src_port;
//     ipv4_rulee.min_dst_port = data->ipv4_pkt->dst_port;
//     ipv4_rulee.allow = val->allow;
//     __u32 keyy = 3;
//     bpf_map_update_elem(&ipv4_rules, &keyy, &ipv4_rulee, BPF_ANY);
// }