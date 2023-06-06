#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>

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
int xdp_red(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Check if eth header is within bounds */
    if ((void *) (eth + 1) > data_end)
    {
        return XDP_DROP;
    }
    /* Don't inspect packet if it's not an IPv4 or IPv6 packet */
    if (eth->h_proto == bpf_htons(ETH_P_IP) || eth->h_proto == bpf_htons(ETH_P_IPV6))
    {
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
        // /* Swap MAC addresses as appropriate */
        // __builtin_memcpy(eth->h_source, my_mac, ETH_ALEN);
        // __builtin_memcpy(eth->h_dest, target_mac, ETH_ALEN);
        // /* Send packet to new destination */
        // return XDP_TX;
    }

    /* Allow the packet if not IPv4/IPv6 packet */
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

// clang -O2 -g -Wall -target bpf -c redirect.c -o redirect.o
// sudo ip link set dev <ifname> [xdpgeneric | xdpdrv | xdpoffload] obj redirect.o sec xdp