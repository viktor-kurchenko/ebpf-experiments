#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"
#include <string.h>

SEC("tc")
int ping(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        bpf_printk("wrong data size!");
        return TC_ACT_OK;
    }

    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    /* Only actual IP packets are allowed */
    if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        bpf_printk("not IP packet!");
        return TC_ACT_OK;
    }

    /* We handle only UDP traffic */
    if (ip->protocol != IPPROTO_UDP) {
        bpf_printk("not UDP datagram!");
        return TC_ACT_OK;
    }

    if (udp->dest != bpf_ntohs(1234)) {
        bpf_printk("wrong UDP port!");
        return TC_ACT_OK;
    }

    unsigned int payload_size = bpf_ntohs(udp->len) - sizeof(*udp);
    unsigned char *payload = (unsigned char *)udp + sizeof(*udp);

    if ((void *)payload + payload_size > data_end) {
        bpf_printk("bad payload!");
        return TC_ACT_OK;
    }

    bpf_printk("processing UDP datagram: %s", payload);

    char *c = "___";
    int off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    bpf_skb_store_bytes(skb, off, c, strlen(c), BPF_F_RECOMPUTE_CSUM);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
