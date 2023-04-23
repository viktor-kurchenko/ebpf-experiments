#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"
#include <string.h>

SEC("tc")
int modify_payload(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        bpf_printk("wrong data size!");
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    struct iphdr  *ip  = (data + sizeof(struct ethhdr));
    struct tcphdr *tcp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    /* Only actual IP packets are allowed */
    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        bpf_printk("not IP packet!");
        return TC_ACT_OK;
    }

    /* We handle only TCP traffic */
    if (ip->protocol != IPPROTO_TCP) {
        bpf_printk("not TCP segment!");
        return TC_ACT_OK;
    }

    if (tcp->dest != bpf_ntohs(80)) {
//        bpf_printk("wrong TCP port!");
        return TC_ACT_OK;
    }

    unsigned int payload_size = bpf_ntohs(tcp->doff << 2) - sizeof(*tcp);
    unsigned char *payload = (unsigned char *)tcp + sizeof(*tcp);

    if ((void *)payload + payload_size > data_end) {
        bpf_printk("bad payload!");
        return TC_ACT_OK;
    }

    bpf_printk("TCP segment payload: %s", payload);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
