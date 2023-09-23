#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_data);

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "장치를 열 수 없습니다: %s\n", errbuf);
        return 1;
    }
    
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    
    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_data) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char *message;
    
    eth_header = (struct ether_header *)packet_data;
    ip_header = (struct ip *)(packet_data + ETHER_HDR_LEN);
    tcp_header = (struct tcphdr *)(packet_data + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
    message = (char *)(packet_data + ETHER_HDR_LEN + (ip_header->ip_hl << 2) + (tcp_header->doff << 2));
    
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    
    printf("Message: %.16s\n", message);
    
    printf("\n");
}
