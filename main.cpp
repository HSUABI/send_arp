#include <pcap.h>
#include <stdio.h>
#include "protocol_structure.h"
#include "printarr.h"
#include "protocol_check.h"
#include "swap_endian.h"
#include "hex_to_ip.h"
#define ETHER_LEN 14


void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: pcap_test wlan0 192.168.10.34 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    // My variables , structures 
   struct sniff_ethernet *ethernet;
   struct sniff_ip *ip;
   struct sniff_tcp *tcp;
    u_int size_ip;
    u_int size_tcp;
    u_int size_data;
    u_char* data;
    ethernet = (struct sniff_ethernet*)packet;
    ip = (struct sniff_ip*)(packet+ETHER_LEN);
    size_ip = IP_HL(ip)*4; 
    tcp = (struct sniff_tcp*)(packet+ETHER_LEN+size_ip);
    size_tcp = TH_OFF(tcp)*4;
    data = (u_char*)(packet+ETHER_LEN+size_ip+size_tcp);
    char ip_src_str[16];    // readable ip 
    char ip_dst_str[16];    // readable ip


    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
  }

  pcap_close(handle);
  return 0;
}