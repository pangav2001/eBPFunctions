#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#define IFNAME "xdptut-080a"

#define FORBIDDEN_DST_IP 16845578 // 10.11.1.1

struct boolean
{
    unsigned int present : 1;
};

int main(int argc, char **argv)
{
    int ifindex, loaded, btf_if, bprog_fd, attached, map_fd, updated, contained;

    char *path;
    const char *bobj_name, *bprog_name;

    struct bpf_object *bobj;
    struct bpf_program *bprog;
    struct bpf_map *map;

    __be32 key;
    struct boolean value;

    ifindex = if_nametoindex(IFNAME);

    printf("The interface index of %s is:  %d\n", IFNAME, ifindex);

    path = "/home/kali/Desktop/git/github/own/eBPFunctions/Firewall/eBPF/eBPFirewall_kernel.o";

    bobj = bpf_object__open(path);

    bobj_name = bpf_object__name(bobj);

    printf("The object name is: %s\n", bobj_name);

    loaded = bpf_object__load(bobj);

    printf("If zero then program was loaded: %d\n", loaded);

    btf_if = bpf_object__btf_fd(bobj);

    printf("BTF fd is: %d\n", btf_if);

    bprog = bpf_object__find_program_by_name(bobj, "xdp_firewall_prog");

    bprog_name = bpf_program__section_name(bprog);

    printf("The program section name is %s\n", bprog_name);

    bprog_fd = bpf_program__fd(bprog);

    printf("The prog fd is: %d\n", bprog_fd);

    attached = bpf_xdp_attach(ifindex, bprog_fd, XDP_FLAGS_SKB_MODE, 0);

    if (attached)
        printf("%d\n", attached);

    map = bpf_object__find_map_by_name(bobj, "forbidden_dst_ips");

    if (!map)
        printf("No such map!\n");

    map_fd = bpf_object__find_map_fd_by_name(bobj, "forbidden_dst_ips");

    key = FORBIDDEN_DST_IP;

    value.present = 1;

    updated = bpf_map__update_elem(map, &key, sizeof(__be32), &value, sizeof(struct boolean), BPF_ANY);

    printf("%d\n", updated);

    contained = bpf_map_lookup_elem(map_fd, &key, &value);

    printf("%d\n", value.present);

    // bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, 0);

    bpf_object__close(bobj);

    return 0;
}

// clang -I ../../libbpf/include -o load_xdp load_xdp.c -L ../../libbpf/src -lbpf