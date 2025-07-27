#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("example: pcap-test wlan0\n");
}

// Ethernet Header
struct ethernet_hdr {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};

// IPv4 Header
struct ipv4_hdr {
    uint8_t ip_hl:4, ip_v:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

// TCP Header
struct tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_offx2;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

char* parse(int argc, char* argv[]){
    if(argc != 2){
        usage();
        return NULL;
    }
    return argv[1];
}

int main(int argc, char * argv[]){
    char *dev = parse(argc, argv);
    if (!dev){
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(pcap == NULL){
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res <= 0) continue;

        struct ethernet_hdr *eth = (struct ethernet_hdr *)packet;
        if(ntohs(eth->ether_type) != 0x0800) continue; // IPv4 only

        struct ipv4_hdr *ip = (struct ipv4_hdr *)(packet + sizeof(struct ethernet_hdr));
        if(ip->ip_p != IPPROTO_TCP) continue; // Only TCP packets

        int ip_header_len = ip->ip_hl * 4;
        struct tcp_hdr *tcp = (struct tcp_hdr *)(packet + sizeof(struct ethernet_hdr)+ ip_header_len);
        int tcp_header_len = (tcp->th_offx2 >> 4) * 4;
        const u_char *payload = packet + sizeof(struct ethernet_hdr) + ip_header_len + tcp_header_len;
        int payload_len = header->len - (sizeof(struct ethernet_hdr) + ip_header_len + tcp_header_len);
        if(payload_len < 0) payload_len = 0;

        printf("\nSrc MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = ip->ip_src;
        dst_ip.s_addr = ip->ip_dst;
        printf("Src IP: %s\n", inet_ntoa(src_ip));
        printf("Dst IP: %s\n", inet_ntoa(dst_ip));

        printf("Src Port: %u\n", ntohs(tcp->th_sport));
        printf("Dst Port: %u\n", ntohs(tcp->th_dport));

        printf("Payload: ");
        int limit;
        if (payload_len < 20) {
            limit = payload_len;
        } else {
            limit = 20;
        }
        for(int i = 0; i < limit; i++){
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
