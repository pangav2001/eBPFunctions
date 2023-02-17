#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <linux/in.h>

struct boolean
{
    unsigned int present : 1;
};

// https://docs.kernel.org/bpf/map_array.html
// https://docs.kernel.org/bpf/maps.html
// https://github.com/libbpf/libbpf/wiki/Libbpf:-the-road-to-v1.0#drop-support-for-legacy-bpf-map-declaration-syntax

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct boolean);
    __uint(max_entries, 10);
} forbidden_src_ips SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct boolean);
    __uint(max_entries, 10);
} forbidden_dst_ips SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be16);
    __type(value, struct boolean);
    __uint(max_entries, 10);
} forbidden_dst_ports SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, struct boolean);
    __uint(max_entries, 10);
} forbidden_protocols SEC(".maps");

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 dst_port;
    __u8 protocol;
    struct boolean *forbidden_src;
    struct boolean *forbidden_dst;
    struct boolean *forbidden_port;
    struct boolean *forbidden_proto;

    /* Get the IP header */
    iph = data + sizeof(*eth);

    /* Check if IP header is within bounds */
    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }
    /* Don't inspect packet if it's not an IPv4 packet */
    if (eth->h_proto == htons(ETH_P_IP))
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
        forbidden_src = bpf_map_lookup_elem(&forbidden_src_ips, &src_ip);
        if (forbidden_src && forbidden_src->present)
        {
            return XDP_DROP;
        }
        /* Get the forbidden destination IP from the map */
        forbidden_dst = bpf_map_lookup_elem(&forbidden_dst_ips, &dst_ip);
        if (forbidden_dst && forbidden_dst->present)
        {
            return XDP_DROP;
        }
        /* Get the protocol */
        protocol = iph->protocol;

        /* Get the forbidden protocol from the map */
        forbidden_proto = bpf_map_lookup_elem(&forbidden_protocols, &protocol);
        if (forbidden_proto && forbidden_proto->present)
        {
            return XDP_DROP;
        }
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        {
            /* Get the TCP or UDP header */
            if (protocol == IPPROTO_TCP)
            {
                tcph = data + sizeof(*eth) + sizeof(*iph);

                /* Check if TCP header is within bounds */
                if (tcph + 1 > (struct tcphdr *)data_end)
                    return XDP_DROP;

                /* Get the destination port */
                dst_port = tcph->dest;
            }
            else
            {
                udph = data + sizeof(*eth) + sizeof(*iph);

                /* Check if UDP header is within bounds */
                if (udph + 1 > (struct udphdr *)data_end)
                    return XDP_DROP;

                /* Get the destination port */
                dst_port = udph->dest;
            }

            /* Get the forbidden destination port from the map */
            forbidden_port = bpf_map_lookup_elem(&forbidden_dst_ports, &dst_port);
            if (forbidden_port && forbidden_port->present)
                return XDP_DROP;
        }
    }

    /* Allow the packet */
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

// clang -O2 -g -Wall -target bpf -c eBPFirewall_kernel.c -o eBPFirewall_kernel.o