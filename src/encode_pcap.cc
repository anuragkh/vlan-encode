/**
 * This program reads a pcap trace, embeds 2 VLAN tags per packet in the trace,
 * and writes the modified pcap trace.
 */

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <cstdint>
#include <cstdio>
#include <cassert>
#include <fstream>
#include <map>

std::ofstream f_out;
uint64_t pkt_cnt;
size_t hop_cnt;

template<typename T>
void write(std::ostream& o, const T& val) {
  o.write(reinterpret_cast<const char*>(&val), sizeof(T));
}

uint64_t timeval_to_usec(timeval t) {
  return (uint64_t) t.tv_sec * 1000000ULL + t.tv_usec;
}

struct vlan_header {
  uint16_t vlan_tci;
  uint16_t eth_proto;
};

void packet_handler(u_char*, const pcap_pkthdr* pcap_hdr, const u_char* pkt) {
  uint64_t pkt_ts = timeval_to_usec(pcap_hdr->ts);

  struct ether_header *eth = nullptr;
  struct ip *ip = nullptr;
  struct tcphdr *tcp = nullptr;
  struct udphdr *udp = nullptr;

  // Parse eth header
  eth = (struct ether_header*) pkt;
  if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
    fprintf(stderr, "!!! Not an IP packet !!!\n");
    return;  // We ignore non-IP packets
  }

  // Parse IP header
  ip = (struct ip*) (eth + 1);
  if (ip->ip_p == IPPROTO_TCP) {
    // Parse TCP header
    tcp = (struct tcphdr*) (ip + 1);
  } else if (ip->ip_p == IPPROTO_UDP) {
    udp = (struct udphdr*) (ip + 1);
  } else {
    fprintf(stderr, "!!! Not a TCP/UDP packet !!!\n");
    return;
  }

  /* Write packet with telemetry information */
  // Modified ethernet header
  eth->ether_type = ETHERTYPE_VLAN;
  write(f_out, *eth);

  // New VLAN headers
  for (size_t i = 1; i < hop_cnt; i++) {
    struct vlan_header vlan1 = { i, ETHERTYPE_VLAN };
    struct vlan_header vlan2 = { i, ETHERTYPE_VLAN };
    write(f_out, vlan1);
    write(f_out, vlan2);
  }

  struct vlan_header vlan1 = { hop_cnt, ETHERTYPE_VLAN };
  struct vlan_header vlan2 = { hop_cnt, ETHERTYPE_IP };
  write(f_out, vlan1);
  write(f_out, vlan2);

  // Unmodified IP header
  write(f_out, *ip);

  // Unmodified TCP/UDP header
  if (tcp != nullptr) {
    write(f_out, *tcp);
  } else {
    write(f_out, *udp);
  } // Ignore remainder of the packet

  // Report progress
  if (++pkt_cnt % 100 == 0) {
    fprintf(stderr, "Processed %lld packets\n", pkt_cnt);
  }
}

int main(int argc, char** argv) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s [input] [output] [hop-count]\n", argv[0]);
    return 1;
  }

  char* in = argv[1];
  char* out = argv[2];
  hop_cnt = atoi(argv[3]);

  f_out.open(out, std::ios_base::out | std::ios_base::ate);

  pkt_cnt = 0;
  char errbuff[PCAP_ERRBUF_SIZE];

  pcap_t* pcap = pcap_open_offline(in, errbuff);
  if (pcap == NULL) {
    fprintf(stderr, "pcap_open_offline() failure: %s\n", errbuff);
    return 1;
  }

  // start packet processing loop
  if (pcap_loop(pcap, 0, packet_handler, NULL) < 0) {
    fprintf(stderr, "pcap_loop() failure: %s\n", pcap_geterr(pcap));
  }

  fprintf(stderr, "[END] Processed %lld packets\n", pkt_cnt);
  f_out.close();

  return 0;
}
