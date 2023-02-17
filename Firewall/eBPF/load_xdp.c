#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#define IFNAME "xdptut-080a"

#define FORBIDDEN_DST_IP 16845578 // 10.11.1.1
#define FORBIDDEN_SRC_IP 33622794 // 10.11.1.2
#define IP_ICMP 1
#define FORBIDDEN_PROTO IP_ICMP
#define PATH "./eBPFirewall_kernel.o"

struct boolean
{
    unsigned int present : 1;
};

struct bpf_object *bpf_object_open(char *path)
{
    return bpf_object__open(path);
}

const char *bpf_object_name(const struct bpf_object *obj)
{
    return bpf_object__name(obj);
}

void bpf_object_print_name(const struct bpf_object *obj)
{
    const char *name = bpf_object_name(obj);
    if (name)
    {
        printf("The object name is: %s\n", name);
    }
    else
    {
        printf("There was an error getting the name for this BPF object!\n");
        // should print error
    }
}

void bpf_object_load(struct bpf_object *obj)
{
    int loaded = bpf_object__load(obj);
    if (!loaded)
    {
        printf("The BPF object was loaded successfully!\n");
    }
    else
    {
        printf("There was an error loading the BPF object!\n");
        // should print error
    }
    bpf_object_print_name(obj);
}

struct bpf_program *bpf_object_find_program_by_name(const struct bpf_object *obj, const char *name)
{
    struct bpf_program *bprog = bpf_object__find_program_by_name(obj, name);
    if (!bprog)
    {
        printf("No BPF program with name %s is found in BPF object provided!\n", name);
        bpf_object_print_name(obj);
        // should print error
    }
    return bprog;
}

int bpf_program_fd(const struct bpf_program *prog)
{
    int fd = bpf_program__fd(prog);
    if (!fd)
    {
        printf("There was an error getting the file descriptor for the BPF provided!\n");
        // should print error
    }
    return fd;
}

void bpf_program_print_fd(const struct bpf_program *prog)
{
    int fd = bpf_program_fd(prog);
    if (fd)
    {
        printf("The BPF program file descriptor is %d.\n", fd);
    }
}

void bpf_xdp_attach_SKB_simple(int ifindex, int prog_fd)
{
    int attached = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, 0);
    if (attached)
    {
        printf("There was an error attaching the BPF program with file descriptor %d to interface %d!\n", prog_fd, ifindex);
        // should print error
    }
}

struct bpf_map *bpf_object_find_map_by_name(const struct bpf_object *obj, const char *name)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map)
    {
        printf("No map named %s could be found in the given BPF object!\n", name);
        bpf_object_print_name(obj);
        // should print error
    }
    return map;
}

int bpf_object_find_map_fd_by_name(const struct bpf_object *obj, const char *name)
{
    int map_fd = bpf_object__find_map_fd_by_name(obj, name);
    if (map_fd < 0)
    {
        printf("There wqs an error getting the file descriptor for the map named %s associated with the given BPF object!\n", name);
        bpf_object_print_name(obj);
        // should print error
    }
    return map_fd;
}

void bpf_map_update_elem_simple(const struct bpf_object *obj, const char *map_name, const void *key, size_t key_sz, const void *value, size_t value_sz)
{
    struct bpf_map *map = bpf_object_find_map_by_name(obj, map_name);
    int updated = bpf_map__update_elem(map, key, key_sz, value, value_sz, BPF_ANY);
    if (updated)
    {
        printf("There was an error updating element with given key in map named %s!\n", map_name);
        // should print error
    }
}

void rule_update(const struct bpf_object *obj, const char *rule, const void *key, size_t key_size, const void *add)
{
    struct boolean value = {.present = *(const bool *)add};
    // probably (surely) not very (at all) safe for production
    char map_name[20] = "forbidden_";
    bpf_map_update_elem_simple(obj, strcat(map_name, rule), key, key_size, &value, sizeof(value));
}

void forbidden_dst_ip(const struct bpf_object *obj, const void *dst_ip, const bool add)
{
    rule_update(obj, "dst_ips", dst_ip, sizeof(__be32), &add);
}

void forbidden_src_ip(const struct bpf_object *obj, const void *src_ip, const bool add)
{
    rule_update(obj, "src_ips", src_ip, sizeof(__be32), &add);
}

void forbidden_dst_ports(const struct bpf_object *obj, const void *dst_port, const bool add)
{
    rule_update(obj, "protocols", dst_port, sizeof(__be16), &add);
}

void forbidden_protocol(const struct bpf_object *obj, const void *proto, const bool add)
{
    rule_update(obj, "protocols", proto, sizeof(__u8), &add);
}

int main(int argc, char **argv)
{
    int ifindex, bprog_fd;

    struct bpf_object *bobj;
    struct bpf_program *bprog;

    __be32 key_32;
    __u8 key_8;

    ifindex = if_nametoindex(IFNAME);

    printf("The interface index of %s is:  %d\n", IFNAME, ifindex);

    bobj = bpf_object_open(PATH);

    bpf_object_load(bobj);

    bprog = bpf_object_find_program_by_name(bobj, "xdp_firewall_prog");

    bprog_fd = bpf_program_fd(bprog);

    bpf_xdp_attach_SKB_simple(ifindex, bprog_fd);

    key_32 = FORBIDDEN_DST_IP;

    forbidden_dst_ip(bobj, &key_32, false);

    key_32 = FORBIDDEN_SRC_IP;

    forbidden_src_ip(bobj, &key_32, false);

    key_8 = FORBIDDEN_PROTO;

    forbidden_protocol(bobj, &key_8, false);

    // bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, 0);

    bpf_object__close(bobj);

    return 0;
}

// clang -I ../../libbpf/include -o load_xdp load_xdp.c -L ../../libbpf/src -lbpf