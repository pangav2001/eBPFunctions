#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define true 1
#define false 0

#define IFNAME "xdptut-080a"

#define FORBIDDEN_DST_IP "10.11.1.1"
#define FORBIDDEN_SRC_IP "10.11.1.2"
#define FORBIDDEN_PROTO IPPROTO_ICMP
#define FORBIDDEN_PORT IPPORT_ECHO

#define PATH "./eBPFirewall_kernel.o"

__be32 get_ip_address_in_nbo(const char *ip) {
  in_addr_t ip_addr = inet_addr(ip);
  return (__be32) ip_addr;
}

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
    // probably (surely) not very (at all) safe for production
    char map_name[20] = "forbidden_";
    bpf_map_update_elem_simple(obj, strcat(map_name, rule), key, key_size, add, sizeof(_Bool));
}

void forbidden_dst_ip(const struct bpf_object *obj, const void *dst_ip, const _Bool add)
{
    rule_update(obj, "dst_ips", dst_ip, sizeof(__be32), &add);
}

void forbidden_src_ip(const struct bpf_object *obj, const void *src_ip, const _Bool add)
{
    rule_update(obj, "src_ips", src_ip, sizeof(__be32), &add);
}

void forbidden_dst_port(const struct bpf_object *obj, const void *dst_port, const _Bool add)
{
    rule_update(obj, "dst_ports", dst_port, sizeof(__be16), &add);
}

void forbidden_protocol(const struct bpf_object *obj, const void *proto, const _Bool add)
{
    rule_update(obj, "protocols", proto, sizeof(__u8), &add);
}

void reuse_pinned_maps(const struct bpf_object *obj, const char *pin_path) {
    char *maps[20] = {"forbidden_src_ips", "forbidden_dst_ips", "forbidden_dst_ports", "forbidden_protocols"};
    char temp_pin_path[50];
    int pinned_map_fd;
    struct bpf_map *map;
    for (int i = 0; i < 4; i++) {
        strncpy(temp_pin_path, pin_path, 50);
        strcat(temp_pin_path, maps[i]);
        pinned_map_fd = bpf_obj_get(temp_pin_path);
        map = bpf_object_find_map_by_name(obj, maps[i]);
        if (bpf_map__reuse_fd(map, pinned_map_fd)) {
            printf("There was an error reusing pinned map named %s located(?) at %s!\n", maps[i], temp_pin_path);
            bpf_object_print_name(obj);
            // should print error
        }
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *bobj;

    __be32 key_32;
    // __be16 key_16;
    __u8 key_8;

    bobj = bpf_object_open(PATH);

    reuse_pinned_maps(bobj, "/sys/fs/bpf/xdp_firewall_prog/");

    bpf_object_load(bobj);

    key_32 = get_ip_address_in_nbo(FORBIDDEN_DST_IP);

    forbidden_dst_ip(bobj, &key_32, false);

    key_32 = get_ip_address_in_nbo(FORBIDDEN_DST_IP);

    forbidden_dst_ip(bobj, &key_32, false);

    key_32 = get_ip_address_in_nbo(FORBIDDEN_SRC_IP);

    forbidden_src_ip(bobj, &key_32, false);

    key_8 = FORBIDDEN_PROTO;

    forbidden_protocol(bobj, &key_8, false);

    // key_16 = FORBIDDEN_PORT;

    // forbidden_dst_port(bobj, &key_16, false);

    // bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, 0);

    bpf_object__close(bobj);

    return 0;
}

// clang -Wall -I ../../libbpf/include -o add_rules.out add_rules.c -L ../../libbpf/src -lbpf