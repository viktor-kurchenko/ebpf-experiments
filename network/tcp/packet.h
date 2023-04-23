#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

#define ETH_P_IP	0x0800		
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

// Returns the protocol byte for an IP packet, 0 for anything else
// static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)
unsigned char lookup_protocol(struct xdp_md *ctx)
{
    unsigned char protocol = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP        
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}

void print_udp_payload(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    unsigned int payload_size;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    unsigned char *payload;

    if ((void *)eth + sizeof(*eth) > data_end) {
        bpf_printk("not ethernet!");
        return;
    }

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        bpf_printk("ip error!");
        return;
    }

    if (ip->protocol != IPPROTO_UDP) {
        bpf_printk("not udp!");
        return;
    }

    udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end) {
        bpf_printk("udp error!");
        return;
    }

//    if (udp->dest != bpf_ntohs(1234)) {
//        bpf_printk("udp port error!");
//        return;
//    }

    payload_size = bpf_ntohs(udp->len) - sizeof(*udp) - 1;
    bpf_printk("UDP payload size: %d", payload_size);

    // Point to start of payload.
    payload = (unsigned char *)udp + sizeof(*udp);
    if ((void *)payload + payload_size > data_end) {
        bpf_printk("payload error!");
        return;
    }

    bpf_printk("Payload: %s", payload);
}
