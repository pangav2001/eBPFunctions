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

#define PATH "./eBPF_firewall.o"

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
    char *maps[20] = {"ipv4_rules", "ipv6_rules"};
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
__u32 get_wildcard_mask(__u8 prefix_len)
{
    return prefix_len ? ~(~0 << (32 - prefix_len)) : ~0;
}
void create_ipv4_rule(struct IPv4Rule *ipv4_rule, char src_ip[], __u8 src_prefix_len, char dst_ip[], __u8 dst_prefix_len, 
    __u16 min_src_port, __u16 max_src_port, __u16 min_dst_port, __u16 max_dst_port, __u8 protocol, bool allow) {
        ipv4_rule->src_ip = ntohl(get_ip_address_in_nbo(src_ip));
        ipv4_rule->src_ip_wildcard_mask = get_wildcard_mask(src_prefix_len);
        ipv4_rule->dst_ip = ntohl(get_ip_address_in_nbo(dst_ip));
        ipv4_rule->dst_ip_wildcard_mask = get_wildcard_mask(dst_prefix_len);
        ipv4_rule->min_src_port = min_src_port;
        ipv4_rule->max_src_port = max_src_port;
        ipv4_rule->min_dst_port = min_dst_port;
        ipv4_rule->max_dst_port = max_dst_port;
        ipv4_rule->protocol = protocol;
        ipv4_rule->allow = allow;
}

void print_ipv4_rule(struct IPv4Rule *ipv4_rule) {
    printf("Src IP: %u, Dst IP: %u, Src Wildcard Mask: %u, Dst Wildcard Mask: %u\n", ipv4_rule->src_ip, ipv4_rule->dst_ip, ipv4_rule->src_ip_wildcard_mask, ipv4_rule->dst_ip_wildcard_mask);
}

void create_ipv6_rule(struct IPv6Rule *ipv6_rule, char src_ip[], __u8 src_prefix_len, char dst_ip[], __u8 dst_prefix_len, 
    __u16 min_src_port, __u16 max_src_port, __u16 min_dst_port, __u16 max_dst_port, __u8 protocol, bool allow) {
        inet_pton(AF_INET6, src_ip, &ipv6_rule->src_ip);
        ipv6_rule->src_ip_wildcard_mask = in6addr_any;
        inet_pton(AF_INET6, dst_ip, &ipv6_rule->dst_ip);
        ipv6_rule->dst_ip_wildcard_mask = in6addr_any;
        ipv6_rule->min_src_port = min_src_port;
        ipv6_rule->max_src_port = max_src_port;
        ipv6_rule->min_dst_port = min_dst_port;
        ipv6_rule->max_dst_port = max_dst_port;
        ipv6_rule->protocol = protocol;
        ipv6_rule->allow = allow;
}

int main(int argc, char **argv)
{
    struct bpf_object *bobj;

    bobj = bpf_object_open(PATH);

    reuse_pinned_maps(bobj, "/sys/fs/bpf/xdp_firewall/");

    bpf_object_load(bobj);
    struct IPv4Rule ipv4_rule;
    const char map_name[] = "ipv4_rules";
    __u32 key = 0;
    create_ipv4_rule(&ipv4_rule, "0.0.0.0", 0, "192.168.133.128", 32, 0, 65535, 0, 65535, IPPROTO_ICMP, true);
    print_ipv4_rule(&ipv4_rule);
    bpf_map_update_elem_simple(bobj, map_name, &key, sizeof(key), &ipv4_rule, sizeof(ipv4_rule));
    key = 1;
    create_ipv4_rule(&ipv4_rule, "0.0.0.0", 0, "0.0.0.0", 0, 0, 65535, 0, 65535, 255, false);
    print_ipv4_rule(&ipv4_rule);
    bpf_map_update_elem_simple(bobj, map_name, &key, sizeof(key), &ipv4_rule, sizeof(ipv4_rule));
    // key = 2;
    // bpf_map_update_elem_simple(bobj, map_name, &key, sizeof(key), &ipv4_ruleee, sizeof(ipv4_ruleee));
    bpf_object__close(bobj);
    
    return 0;
}

// clang -Wall -I ../../libbpf/include -o add_rules_new.out add_rules_new.c -L ../../libbpf/src -lbpf