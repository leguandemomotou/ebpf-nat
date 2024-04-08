# Designing-And-Developing-for-GIS
A professional required course for the major of geographic information science. The course content is mainly for the development of WebGIS. The reference book is the development guide for ArcGIS API for JavaScript.
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <time.h>
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <time.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_helpers.h"

#define PIN_GLOBAL_NS           2
#define uint8_t  char
#define uint16_t  unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long

#define IS_PSEUDO 0x10
#define TCP_DPORT_OFF        (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define IP_CSUM_OFFSET       (sizeof(struct ethhdr) + offsetof(struct iphdr, check))
#define TCP_CSUM_OFFSET      (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFFSET      (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define ICMP_CSUM_OFFSET      (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))

#define IP_CSUM_OFF 	     (ETH_HLEN + offsetof(struct iphdr, check))
#define TOS_OFF              (ETH_HLEN + offsetof(struct iphdr, tos))
#define TCP_CSUM_OFF         (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_PROTO_OFF offsetof(struct iphdr, protocol)


#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#define MAX_ELEM 10000

struct nat_info {
	uint32_t src_ip;
	uint32_t dst_ip;
};

struct nat_ip_port_info {
	__u32 port;
        __u32 ip;
	
};

struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
};

struct nat_gateway_mac{
        uint8_t mac0;
        uint8_t mac1;
	uint8_t mac2;
	uint8_t mac3;
	uint8_t mac4;
	uint8_t mac5;
};

#if 0
struct bpf_elf_map SEC("maps") gateway_mac_map = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__u32),
	.size_value = sizeof(struct nat_gateway_mac),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") nat_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct nat_info),
        .size_value = sizeof(__u32),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") reverse_nat_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct nat_info),
        .size_value = sizeof(__u32),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};


struct bpf_elf_map SEC("maps") nat_port_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct nat_ip_port_info),
        .size_value = sizeof(struct nat_ip_port_info),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") reverse_port_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct nat_ip_port_info),
        .size_value = sizeof(struct nat_ip_port_info),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") srcip_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u32),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") nat_ip_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u32),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") nat_local_port_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(__u16),
        .size_value = sizeof(__u16),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};

struct bpf_elf_map SEC("maps") reverse_local_port_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(__u16),
        .size_value = sizeof(__u16),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = MAX_ELEM,
};
#endif
struct bpf_elf_map SEC("maps") reverse_wireguard_map = {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u32),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem = 10000,
};

#define TCP_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))

#if 0
static inline int ip_tcp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct iphdr *iph,__u32 *ip_entry)
{
        uint32_t l4sum = 0;
        uint32_t new_ip ,old_ip;
        uint32_t new_port ,old_port;
        uint8_t *mac_entry = NULL;
        uint64_t nh_off;
        uint32_t  l3sum = 0;
        __u32 *action_entry = NULL;
	
        uint32_t tmp_ip;
        uint16_t tmp_port;
       
	new_ip = *ip_entry;
        mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
        if(mac_entry)
        {
        	uint8_t *gateway_mac = mac_entry;
                eth->h_dest[0] = gateway_mac[0];
                eth->h_dest[1] = gateway_mac[1];
                eth->h_dest[2] = gateway_mac[2];
                eth->h_dest[3] = gateway_mac[3];
                eth->h_dest[4] = gateway_mac[4];
                eth->h_dest[5] = gateway_mac[5];
        }

                        // __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);

        bpf_map_update_elem(&srcip_map, (const void *)&(iph->daddr), (__u32 *)&(iph->saddr), 0);
        old_ip = (iph->daddr);
        tmp_ip = old_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
        iph->daddr = (new_ip);

        old_ip = iph->saddr;
        new_ip  = tmp_ip;
        iph->saddr = tmp_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);


        bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
        bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);

	return 0;
}

static inline int reserve_ip_tcp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct iphdr *iph,__u32 *ip_entry)
{
	uint32_t l4sum = 0;
        uint32_t new_ip ,old_ip;
        uint32_t new_port ,old_port;
        uint8_t *mac_entry = NULL;
        uint64_t nh_off;
        uint32_t  l3sum = 0;
	uint32_t tmp_ip;
        uint16_t tmp_port;
        __u32 * action_entry = bpf_map_lookup_elem(&srcip_map, &(iph->daddr));
        if(action_entry)
        {
        	tmp_ip = iph->daddr;
                //uint8_t src_mac[ETH_ALEN] = {0x52,0x54,0x96,0x7b,0xd1,0xe4};
                //uint8_t dst_mac[ETH_ALEN] = {0x52,0x54,0x96,0xcd,0x9c,0x24};
                 uint8_t *mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
                if(mac_entry)
                {
               		uint8_t *gateway_mac = mac_entry;
                        eth->h_dest[0] = gateway_mac[0];
                        eth->h_dest[1] = gateway_mac[1];
                        eth->h_dest[2] = gateway_mac[2];
                        eth->h_dest[3] = gateway_mac[3];
                        eth->h_dest[4] = gateway_mac[4];
                        eth->h_dest[5] = gateway_mac[5];
                }
		
                old_ip = iph->daddr;
                new_ip = *action_entry;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                iph->daddr = new_ip;

                old_ip = iph->saddr;
                new_ip = tmp_ip;
                iph->saddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
	}

	return 0;
}

static inline int tcp_port_ip_tcp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct tcphdr* tcp,struct iphdr *iph,struct nat_ip_port_info *ip_port_entry)
{
	uint32_t tmp_ip,old_ip,new_ip;
        uint16_t tmp_port;
	uint32_t new_port ,old_port;
	uint32_t  l3sum = 0;
	uint32_t  l4sum = 0;
        new_ip  = ip_port_entry->ip;
        uint8_t *mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
    
	if(mac_entry)
        {
        	uint8_t *gateway_mac = mac_entry;
                eth->h_dest[0] = gateway_mac[0];
                eth->h_dest[1] = gateway_mac[1];
                eth->h_dest[2] = gateway_mac[2];
                eth->h_dest[3] = gateway_mac[3];
                eth->h_dest[4] = gateway_mac[4];
                eth->h_dest[5] = gateway_mac[5];
        }

	struct nat_ip_port_info reverse_tcp_port_key,reverse_tcp_port_value;
	reverse_tcp_port_key.ip =  iph->daddr;
	reverse_tcp_port_key.port =  ntohs(tcp->source);
	reverse_tcp_port_value.ip = iph->saddr;
	reverse_tcp_port_value.port =  ntohs(tcp->dest);

	bpf_map_update_elem(&reverse_port_map, (const void *)&reverse_tcp_port_key, (struct nat_ip_port_info *)&reverse_tcp_port_value, 0);
        old_ip = (iph->daddr);
        tmp_ip = old_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
        iph->daddr = (new_ip);

        old_ip = iph->saddr;
        new_ip  = tmp_ip;
        iph->saddr = tmp_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);

        old_port = (tcp->dest);
        tmp_port = old_port;
        new_port = htons(ip_port_entry->port);
        tcp->dest = htons(ip_port_entry->port);
        l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);

        bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
        bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l4sum, 0);
        bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);

	return 0;
}

static inline  int reverse_tcp_port_ip_tcp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct tcphdr* tcp,struct iphdr *iph)
{
        uint32_t tmp_ip,new_ip,old_ip;
        uint16_t tmp_port;
	uint32_t l3sum = 0 ,l4sum = 0;
	uint32_t new_port,old_port;
	struct nat_ip_port_info reverse_tcp_port_key,reverse_tcp_port_value;
	reverse_tcp_port_key.ip = iph->daddr;
	reverse_tcp_port_key.port = ntohs(tcp->dest);
        struct nat_ip_port_info *ip_port_entry = bpf_map_lookup_elem(&reverse_port_map, &reverse_tcp_port_key);
        if(ip_port_entry)
        {
        	tmp_ip = iph->daddr;
                uint8_t *mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
                if(mac_entry)
                {
                	uint8_t *gateway_mac = mac_entry;
                        eth->h_dest[0] = gateway_mac[0];
                        eth->h_dest[1] = gateway_mac[1];
                        eth->h_dest[2] = gateway_mac[2];
                        eth->h_dest[3] = gateway_mac[3];
                        eth->h_dest[4] = gateway_mac[4];
                        eth->h_dest[5] = gateway_mac[5];
                }

                old_port = (tcp->source);
                tmp_port = old_port;
                new_port = htons((uint16_t)ip_port_entry->port);
		tcp->source = new_port;
                l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);
                
                old_ip = iph->daddr;
                new_ip = ip_port_entry->ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                iph->daddr = new_ip;

                old_ip = iph->saddr;
                new_ip = tmp_ip;
                iph->saddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l4sum, 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
        }
	
	return 0;
}

static inline  int local_port_tcp_dnat(struct __sk_buff *skb,struct tcphdr* tcp,__u16 *port_entry)
{
	uint16_t tmp_port,dport;
	uint32_t new_port,old_port;
	uint32_t l4sum = 0;
	old_port = (tcp->dest);
	dport = ntohs(tcp->dest);
	tmp_port = ntohs(tcp->source);
	new_port = htons(*port_entry);
	tcp->dest = new_port;
	l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);
	bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l4sum, 0);
	bpf_map_update_elem(&reverse_local_port_map, (const void *)&(tmp_port), (const void *)&dport, 0);
	return 0;
}

static inline  int reverse_local_port_tcp_dnat(struct __sk_buff *skb,struct tcphdr* tcp,__u16 *port_entry)
{
        uint16_t tmp_port,dport;
        uint32_t new_port,old_port;
        uint32_t l4sum = 0;
	
	tmp_port = ntohs(tcp->dest);
	uint16_t *reverse_port_entry = bpf_map_lookup_elem(&reverse_local_port_map, &tmp_port);
	if(reverse_port_entry)
	{
		old_port = (tcp->source);
		new_port = htons(*port_entry);
		tcp->source = new_port;
		l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);
		bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l4sum, 0);
	}
   
        return 0;
}
#endif
static inline int wireguard_tcp_snat(struct __sk_buff *skb,struct iphdr *iph,__u32 *ip_entry)
{
	__u32 old_ip,new_ip;
	uint32_t l3sum = 0;
	//LOG("00dnat------=====================%u============",*ip_entry);
        __u32 tmp_ip = *ip_entry;
        if(tmp_ip  != iph->daddr)
        {
        	old_ip = iph->daddr;
                new_ip = tmp_ip;
                __u32 src = iph->saddr;
                l3sum = 0;
                iph->daddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, TCP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
          //      LOG("11dnat------===========%u==========%u============",src,tmp_ip);
        }

	return 0;
}

static inline int wireguard_udp_snat(struct __sk_buff *skb,struct iphdr *iph,__u32 *ip_entry)
{
        __u32 old_ip,new_ip;
        uint32_t l3sum = 0;
       // LOG("00udp  dnat------=====================%u============",*ip_entry);
        __u32 tmp_ip = *ip_entry;
        if(tmp_ip  != iph->daddr)
        {
                old_ip = iph->daddr;
                new_ip = tmp_ip;
                __u32 src = iph->saddr;
                l3sum = 0;
                iph->daddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
         //       LOG("11dnat------===========%u==========%u============",src,tmp_ip);
        }

        return 0;
}

static inline int wireguard_icmp_snat(struct __sk_buff *skb,struct iphdr *iph,__u32 *ip_entry)
{
        __u32 old_ip,new_ip;
        uint32_t l3sum = 0;
       // LOG("00udp  dnat------=====================%u============",*ip_entry);
        __u32 tmp_ip = *ip_entry;
        if(tmp_ip  != iph->daddr)
        {
                old_ip = iph->daddr;
                new_ip = tmp_ip;
                __u32 src = iph->saddr;
                l3sum = 0;
                iph->daddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, ICMP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
        }

        return 0;	
}

#if 0
static inline int ip_udp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct iphdr *iph,__u32 *ip_entry)
{
        uint32_t l4sum = 0;
        uint32_t new_ip ,old_ip;
        uint32_t new_port ,old_port;
        uint8_t *mac_entry = NULL;
        uint64_t nh_off;
        uint32_t  l3sum = 0;
        __u32 *action_entry = NULL;

        uint32_t tmp_ip;
        uint16_t tmp_port;

        new_ip = *ip_entry;
        mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
        if(mac_entry)
        {
                uint8_t *gateway_mac = mac_entry;
                eth->h_dest[0] = gateway_mac[0];
                eth->h_dest[1] = gateway_mac[1];
                eth->h_dest[2] = gateway_mac[2];
                eth->h_dest[3] = gateway_mac[3];
                eth->h_dest[4] = gateway_mac[4];
                eth->h_dest[5] = gateway_mac[5];
        }

                        // __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);

        bpf_map_update_elem(&srcip_map, (const void *)&(iph->daddr), (__u32 *)&(iph->saddr), 0);
        old_ip = (iph->daddr);
        tmp_ip = old_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
        iph->daddr = (new_ip);

        old_ip = iph->saddr;
        new_ip  = tmp_ip;
        iph->saddr = tmp_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);


        bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
        bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);

        return 0;
}

static inline int reserve_ip_udp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct iphdr *iph,__u32 *ip_entry)
{
         uint32_t l4sum = 0;
        uint32_t new_ip ,old_ip;
        uint32_t new_port ,old_port;
        uint8_t *mac_entry = NULL;
        uint64_t nh_off;
        uint32_t  l3sum = 0;
        uint32_t tmp_ip;
        uint16_t tmp_port;
        __u32 * action_entry = bpf_map_lookup_elem(&srcip_map, &(iph->daddr));
        if(action_entry)
        {
                tmp_ip = iph->daddr;
                //uint8_t src_mac[ETH_ALEN] = {0x52,0x54,0x96,0x7b,0xd1,0xe4};
                //uint8_t dst_mac[ETH_ALEN] = {0x52,0x54,0x96,0xcd,0x9c,0x24};
                 uint8_t *mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
                if(mac_entry)
                {
                        uint8_t *gateway_mac = mac_entry;
                        eth->h_dest[0] = gateway_mac[0];
                        eth->h_dest[1] = gateway_mac[1];
                        eth->h_dest[2] = gateway_mac[2];
                        eth->h_dest[3] = gateway_mac[3];
                        eth->h_dest[4] = gateway_mac[4];
                        eth->h_dest[5] = gateway_mac[5];
                }

                old_ip = iph->daddr;
                new_ip = *action_entry;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                iph->daddr = new_ip;

                old_ip = iph->saddr;
                new_ip = tmp_ip;
                iph->saddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
        }

        return 0;
}

static inline int udp_port_ip_udp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct udphdr* udp,struct iphdr *iph,struct nat_ip_port_info *ip_port_entry)
{
        uint32_t tmp_ip,old_ip,new_ip;
        uint16_t tmp_port;
        uint32_t new_port ,old_port;
        uint32_t  l3sum = 0;
        uint32_t  l4sum = 0;
        new_ip  = ip_port_entry->ip;
        uint8_t *mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));

        if(mac_entry)
        {
                uint8_t *gateway_mac = mac_entry;
                eth->h_dest[0] = gateway_mac[0];
                eth->h_dest[1] = gateway_mac[1];
                eth->h_dest[2] = gateway_mac[2];
                eth->h_dest[3] = gateway_mac[3];
                eth->h_dest[4] = gateway_mac[4];
                eth->h_dest[5] = gateway_mac[5];
        }

        struct nat_ip_port_info reverse_tcp_port_key,reverse_tcp_port_value;
        reverse_tcp_port_key.ip =  iph->daddr;
        reverse_tcp_port_key.port =  ntohs(udp->source);
        reverse_tcp_port_value.ip = iph->saddr;
        reverse_tcp_port_value.port =  ntohs(udp->dest);

        bpf_map_update_elem(&reverse_port_map, (const void *)&reverse_tcp_port_key, (struct nat_ip_port_info *)&reverse_tcp_port_value, 0);
        old_ip = (iph->daddr);
        tmp_ip = old_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
        iph->daddr = (new_ip);

        old_ip = iph->saddr;
        new_ip  = tmp_ip;
        iph->saddr = tmp_ip;
        l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);

        old_port = (udp->dest);
        tmp_port = old_port;
        new_port = htons(ip_port_entry->port);
        udp->dest = htons(ip_port_entry->port);
        l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);

        bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
        bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l4sum, 0);
        bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);

        return 0;
}

static inline  int reverse_udp_port_ip_udp_dnat(struct __sk_buff *skb,struct ethhdr *eth,struct udphdr* udp,struct iphdr *iph)
{
        uint32_t tmp_ip,new_ip,old_ip;
        uint16_t tmp_port;
        uint32_t l3sum = 0 ,l4sum = 0;
        uint32_t new_port,old_port;
        struct nat_ip_port_info reverse_tcp_port_key,reverse_tcp_port_value;
        reverse_tcp_port_key.ip = iph->daddr;
        reverse_tcp_port_key.port = ntohs(udp->dest);
        struct nat_ip_port_info *ip_port_entry = bpf_map_lookup_elem(&reverse_port_map, &reverse_tcp_port_key);
        if(ip_port_entry)
        {
                tmp_ip = iph->daddr;
                uint8_t *mac_entry = bpf_map_lookup_elem(&gateway_mac_map, &(iph->daddr));
                if(mac_entry)
                {
                        uint8_t *gateway_mac = mac_entry;
                        eth->h_dest[0] = gateway_mac[0];
                        eth->h_dest[1] = gateway_mac[1];
                        eth->h_dest[2] = gateway_mac[2];
                        eth->h_dest[3] = gateway_mac[3];
                        eth->h_dest[4] = gateway_mac[4];
                        eth->h_dest[5] = gateway_mac[5];
                }

                old_port = (udp->source);
                tmp_port = old_port;
                new_port = htons((uint16_t)ip_port_entry->port);
                udp->source = new_port;
                l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);

                old_ip = iph->daddr;
                new_ip = ip_port_entry->ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                iph->daddr = new_ip;

                old_ip = iph->saddr;
                new_ip = tmp_ip;
                iph->saddr = new_ip;
                l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, l3sum);
                bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
                bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l4sum, 0);
                bpf_l3_csum_replace(skb, IP_CSUM_OFFSET , 0, l3sum, 0);
        }

        return 0;
}

static inline  int local_port_udp_dnat(struct __sk_buff *skb,struct udphdr* udp,__u16 *port_entry)
{
        uint16_t tmp_port,dport;
        uint32_t new_port,old_port;
        uint32_t l4sum = 0;
        old_port = (udp->dest);
        dport = ntohs(udp->dest);
        tmp_port = ntohs(udp->source);
        new_port = htons(*port_entry);
        udp->dest = new_port;
        l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);
        bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l4sum, 0);
        bpf_map_update_elem(&reverse_local_port_map, (const void *)&(tmp_port), (const void *)&dport, 0);
        return 0;
}

static inline  int reverse_local_port_udp_dnat(struct __sk_buff *skb,struct udphdr* udp,__u16 *port_entry)
{
        uint16_t tmp_port,dport;
        uint32_t new_port,old_port;
        uint32_t l4sum = 0;

        tmp_port = ntohs(udp->dest);
        uint16_t *reverse_port_entry = bpf_map_lookup_elem(&reverse_local_port_map, &tmp_port);
        if(reverse_port_entry)
        {
                old_port = (udp->source);
                new_port = htons(*port_entry);
                udp->source = new_port;
                l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, l4sum);
                bpf_l4_csum_replace(skb, UDP_CSUM_OFFSET, 0, l4sum, 0);
        }

        return 0;
}
#endif

static inline int dnat(struct __sk_buff *skb)
{
        void *data_end = (void *)(unsigned long long)skb->data_end;
    	void *data = (void *)(unsigned long long)skb->data;               
        uint32_t ipproto;
	uint32_t l4sum = 0;
	uint32_t new_ip ,old_ip;
	uint32_t new_port ,old_port;
	uint8_t *mac_entry = NULL;
        uint64_t nh_off;
	uint32_t  l3sum = 0;
	__u32 *ip_entry = NULL;
	struct ethhdr *eth = (struct ethhdr *)data;
	struct nat_ip_port_info *ip_port_entry = NULL;
	struct tcphdr* tcp = NULL;
	uint32_t flag = 0;
#if 1
        nh_off = sizeof(*eth);
        if ((void *)data + nh_off > data_end) {
                return 2;
        }


        struct iphdr *iph = data + nh_off;
        struct nat_ip_port_info ip_port_info;
        if ((void *)iph + sizeof(*iph) > data_end)
        {
                return 2;
        }		

	
	if (iph->protocol == IPPROTO_TCP)
	{
		ip_entry = bpf_map_lookup_elem(&reverse_wireguard_map, &(iph->saddr));
		if(ip_entry)
		{
			if(*ip_entry != iph->daddr)
			{
			//	LOG("wireguard ingress tcp------========src ip%u==========dst ip%u===============\n",iph->saddr,iph->daddr);
				wireguard_tcp_snat(skb,iph,ip_entry);
				flag = 1;
				bpf_clone_redirect(skb, skb->ifindex, 1);
				//bpf_redirect(skb->ifindex, 1);
				return 2;
			}
		}

		#if 0
		if(flag == 0)
		{
        		ip_entry = bpf_map_lookup_elem(&nat_ip_map, &(iph->daddr));
        		if(ip_entry)
        		{
                		if(*ip_entry  != iph->saddr)
                		{
                        		ip_tcp_dnat(skb,eth,iph,ip_entry);
					flag = 1;
                		}
                		else
                		{
                        		reserve_ip_tcp_dnat(skb,eth,iph,ip_entry);
					flag = 1;
                		}
        		}
		}

		if(flag == 0)
		{
                	tcp = (struct tcphdr*)(iph + 1);
                	if ((void *)(tcp + 1) > data_end)
                	{
                        	return 0;
                	}

                	uint16_t tmp_port = ntohs(tcp->dest);
                	uint16_t *local_port_entry = NULL;
                	local_port_entry =  bpf_map_lookup_elem(&nat_local_port_map,(const void *)&tmp_port);
                	if(local_port_entry)
                	{
                        	local_port_tcp_dnat(skb,tcp,local_port_entry);
				flag = 1;
                	}
                	else
                	{
                        	struct nat_ip_port_info nat_ip_port_key;
                        	nat_ip_port_key.port = ntohs(tcp->dest);
                        	nat_ip_port_key.ip   = (iph->daddr);
                        	ip_port_entry = bpf_map_lookup_elem(&nat_port_map,(const void *) &nat_ip_port_key);
                        	if(ip_port_entry)
                        	{
                                	tcp_port_ip_tcp_dnat(skb,eth,tcp,iph,ip_port_entry);
					flag = 1; 
                        	}
                        	else
                        	{
                                	nat_ip_port_key.port = ntohs(tcp->dest);
                                	nat_ip_port_key.ip   = (iph->daddr);
                                	ip_port_entry = bpf_map_lookup_elem(&reverse_port_map, &nat_ip_port_key);
                                	if(ip_port_entry)
                                	{
                                	        reverse_tcp_port_ip_tcp_dnat(skb,eth,tcp,iph);
						flag = 1;
                                	}
                       		}
                	}
		}
		#endif
	}

	data_end = (void *)(unsigned long long)skb->data_end;
	data = (void *)(unsigned long long)skb->data;
	eth = (struct ethhdr *)data;
        nh_off = sizeof(*eth);
        if ((void *)data + nh_off > data_end) {
                return 2;
        }
	
        iph = data + nh_off;
        if ((void *)iph + sizeof(*iph) > data_end)
        {
                return 2;
        }

	if (iph->protocol == IPPROTO_ICMP)
	{

	                ip_entry = bpf_map_lookup_elem(&reverse_wireguard_map, &(iph->saddr));
                //if(ip_entry && 134744072 != iph->saddr)
                if(ip_entry)
                {
                        if(*ip_entry != iph->daddr)
                        {
        //                      LOG("wireguard ingress------udp=======src ip%u========dst ip%u==================\n",iph->saddr,iph->daddr);
                                wireguard_icmp_snat(skb,iph,ip_entry);
                                flag = 1;
                                bpf_clone_redirect(skb, skb->ifindex, 1);
				//bpf_redirect(skb->ifindex, 1);
                                return 2;
                        }
                }

	//	LOG("icmp ingress------icmp=======src ip%u========dst ip%u==================\n",iph->saddr,iph->daddr)
	}
        data_end = (void *)(unsigned long long)skb->data_end;
        data = (void *)(unsigned long long)skb->data;
        eth = (struct ethhdr *)data;
        nh_off = sizeof(*eth);
        if ((void *)data + nh_off > data_end) {
                return 2;
        }

        iph = data + nh_off;
        if ((void *)iph + sizeof(*iph) > data_end)
        {
                return 2;
        }	

	if (iph->protocol == IPPROTO_UDP)
	{
	//	LOG("000000wireguard ingress------udp=======src ip%u========dst ip%u==================\n",iph->saddr,iph->daddr);
                ip_entry = bpf_map_lookup_elem(&reverse_wireguard_map, &(iph->saddr));
                //if(ip_entry && 134744072 != iph->saddr)
		if(ip_entry)
                {
                        if(*ip_entry != iph->daddr)
                        {
	//			LOG("wireguard ingress------udp=======src ip%u========dst ip%u==================\n",iph->saddr,iph->daddr);
                                wireguard_udp_snat(skb,iph,ip_entry);
                                flag = 1;
				bpf_clone_redirect(skb, skb->ifindex, 1);
				//bpf_redirect(skb->ifindex, 1);
				return 2;
                        }
                }
		#if 0
                if(flag == 0)
                {
                        ip_entry = bpf_map_lookup_elem(&nat_ip_map, &(iph->daddr));
                        if(ip_entry)
                        {
                                if(*ip_entry  != iph->saddr)
                                {
                                        ip_udp_dnat(skb,eth,iph,ip_entry);
                                        flag = 1;
				}
				else
                                {
                                        reserve_ip_udp_dnat(skb,eth,iph,ip_entry);
                                        flag = 1;
                                }
                        }
                }

                if(flag == 0)
                {
                        struct udphdr *udp = (struct udphdr*)(iph + 1);
                        if ((void *)(udp + 1) > data_end)
                        {
                                return 0;
                        }

                        uint16_t tmp_port = ntohs(udp->dest);
                        uint16_t *local_port_entry = NULL;
                        local_port_entry =  bpf_map_lookup_elem(&nat_local_port_map,(const void *)&tmp_port);
                        if(local_port_entry)
                        {
                                local_port_udp_dnat(skb,udp,local_port_entry);
                                flag = 1;
                        }
                        else
                        {
                                struct nat_ip_port_info nat_ip_port_key;
                                nat_ip_port_key.port = ntohs(udp->dest);
                                nat_ip_port_key.ip   = (iph->daddr);
                                ip_port_entry = bpf_map_lookup_elem(&nat_port_map,(const void *) &nat_ip_port_key);
                                if(ip_port_entry)
                                {
                                        udp_port_ip_udp_dnat(skb,eth,udp,iph,ip_port_entry);
                                        flag = 1;
                                }
                                else
                                {
                                        nat_ip_port_key.port = ntohs(udp->dest);
                                        nat_ip_port_key.ip   = (iph->daddr);
                                        ip_port_entry = bpf_map_lookup_elem(&reverse_port_map, &nat_ip_port_key);
                                        if(ip_port_entry)
                                        {
                                                reverse_udp_port_ip_udp_dnat(skb,eth,udp,iph);
                                                flag = 1;
                                        }
                                }
                        }
                }
		#endif		
	}
	
	
//	bpf_clone_redirect(skb, skb->ifindex, 0);
#endif
	return 0;
}


/* Test: Verify skb data can be modified */
SEC("test_rewrite_ingress")
int do_test_rewrite(struct __sk_buff *skb)
{
	return dnat(skb);

}
char _license[] SEC("license") = "GPL";

