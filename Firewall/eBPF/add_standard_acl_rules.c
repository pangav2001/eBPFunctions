#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
#define true 1
#define false 0

// #define IFNAME "xdptut-09b3"

// #define FORBIDDEN_DST_IP "10.11.1.1"
// #define FORBIDDEN_DST_IP "192.168.133.128"
// #define FORBIDDEN_SRC_IP "192.168.133.1"
// #define FORBIDDEN_PROTO IPPROTO_ICMP
// #define FORBIDDEN_PORT IPPORT_ECHO

#define PATH "./standard_acl_kern.o"

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
        printf("There was an error getting the file descriptor for the map named %s associated with the given BPF object!\n", name);
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

void reuse_pinned_maps(const struct bpf_object *obj, const char *pin_path) {
    int num_of_maps = 2;
    char *maps[20] = {"ipv4_rules_trie", "ipv6_rules_trie"};
    char temp_pin_path[50];
    int pinned_map_fd;
    struct bpf_map *map;
    for (int i = 0; i < num_of_maps; i++) {
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
struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct ipv6_lpm_key {
        __u32 prefixlen;
        struct in6_addr data;
};

__u32 get_subnet_mask(__u8 prefix_len)
{
    return prefix_len ? ~0 << (32 - prefix_len) : 0;
}

struct ipv4_lpm_key gen_ipv4_key(__u32 prefixlen, __u32 ip) {
        struct ipv4_lpm_key key = {
            .prefixlen = prefixlen,
            .data = ip
        };
        return key;
}

struct ipv6_lpm_key gen_ipv6_key(__u32 prefixlen, struct in6_addr ip) {
        struct ipv6_lpm_key key = {
            .prefixlen = prefixlen,
            .data = ip
        };
        return key;
}

int main(int argc, char **argv)
{
    struct bpf_object *bobj;

    bobj = bpf_object_open(PATH);

    reuse_pinned_maps(bobj, "/sys/fs/bpf/xdp_standard_acl/");

    bpf_object_load(bobj);
    struct ipv4_lpm_key ipv4_key;
    struct ipv6_lpm_key ipv6_key;
    _Bool value;
    ipv4_key = gen_ipv4_key(24, get_ip_address_in_nbo("10.1.0.1"));
    value = true;
    bpf_map_update_elem_simple(bobj, "ipv4_rules_trie", &ipv4_key, sizeof(ipv4_key), &value, sizeof(value));
    bpf_object__close(bobj);
    
    return 0;
}

// clang -Wall -I ../../libbpf/include -o add_standard_acl_rules.out add_standard_acl_rules.c -L ../../libbpf/src -lbpf -lelf