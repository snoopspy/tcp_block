#include <iostream>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "checksum.h"

static pcap_if_t* alldevs;

static pcap_if_t* getDevice() {
  pcap_if_t* d;
  char errbuf[PCAP_ERRBUF_SIZE];
#ifdef WIN32
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
#else
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
#endif
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }

  int i = 0;
  for(d = alldevs; d; d=d->next)
  {
    std::cout << ++i << ". " << d->name << " ";
    if (d->description)
      std::cout << d->description;
    else
      std::cout << "(No description available)";
    std::cout << std::endl;
  }

  if(i == 0)
  {
    printf("\nNo interfaces found! Make sure pcap is installed.\n");
    return NULL;
  }

  printf("Enter the interface number (1-%d):",i);
  int inum; std::cin >> inum;

  if(inum < 1 || inum > i)
  {
      printf("\nInterface number out of range.\n");
      /* Free the device list */
      pcap_freealldevs(alldevs);
      return NULL;
  }

  for(d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
  return d;
}

static pcap_t* openDevice(pcap_if_t* d) {
  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];
#ifdef WIN32
  handle = pcap_open(d->name, 65536, 1, 1, NULL, errbuf);
#else
  handle = pcap_open_live(d->name, 65536, 1, 1, errbuf);
#endif

  if (handle == NULL) {
    fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return NULL;
  }

  uint32_t netmask = 0xFFFFFF;

  //compile the filter
  bpf_program fcode;
  //static const char* filter = "tcp[20:4]=0x47455420";
  //static const char* filter = "tcp and host 58.76.179.113 and len > 60";
  static const char* filter = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420";

  if (pcap_compile(handle, &fcode, filter, 1, netmask) < 0)
  {
     fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
     pcap_freealldevs(alldevs);
     return NULL;
  }

  //set the filter
  if (pcap_setfilter(handle, &fcode) < 0)
  {
     fprintf(stderr,"\nError setting the filter.\n");
     /* Free the device list */
     pcap_freealldevs(alldevs);
     return NULL;
  }

  return handle;
}

static void processPacket(pcap_t* handle, struct pcap_pkthdr* header, const u_char* pkt_data) {
  libnet_ethernet_hdr* ethHdr = (libnet_ethernet_hdr*)pkt_data;
  if (ntohs(ethHdr->ether_type) != ETHERTYPE_IP)
      return;

  libnet_ipv4_hdr* ipHdr = (libnet_ipv4_hdr*)(ethHdr + 1);
  if (ipHdr->ip_p != IPPROTO_TCP)
    return;

  //libnet_tcp_hdr* tcpHdr = (libnet_tcp_hdr*)((u_char*)ipHdr + ipHdr->ip_hl * 4);
  libnet_tcp_hdr* tcpHdr = (libnet_tcp_hdr*)((u_char*)ipHdr + sizeof(libnet_ipv4_hdr));
  if (tcpHdr->th_flags & (TH_RST | TH_FIN)) return;

  int sendBufSize = header->caplen;
  u_char sendBuffer[sendBufSize];
  memcpy(sendBuffer, pkt_data, sendBufSize);

  libnet_ethernet_hdr* sendEthHdr = (libnet_ethernet_hdr*)sendBuffer;
  libnet_ipv4_hdr* sendIpHdr = (libnet_ipv4_hdr*)(sendEthHdr + 1);
  libnet_tcp_hdr* sendTcpHdr = (libnet_tcp_hdr*)((u_char*)sendIpHdr + sizeof(libnet_ipv4_hdr));

  // TO DO(sendEthHdr)

  // TO DO(sendTpHdr)
  //sendIpHdr->ip_tos = 0x44;

  // TO DO(sendTcpHdr)
  sendTcpHdr->th_flags |= TH_RST;

  // Checksum
  tcpHdr->th_sum = htons(tcpChecksum(sendIpHdr, sendTcpHdr));
  //ipHdr->ip_sum = htons(ipChecksum(sendIpHdr));

  int res = pcap_sendpacket(handle, (const u_char*)sendBuffer, sendBufSize);

  std::cout << ntohs(tcpHdr->th_dport) << " res=" << res << std::endl;
}

int main() {
  pcap_if_t* d = getDevice();
  if (d == NULL)
    return -1;

  pcap_t* handle = openDevice(d);
  if (handle == NULL)
    return -1;

  while (true) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = pcap_next_ex(handle, &header, &pkt_data);
    if (res == 0) continue;
    if (res < 0) break;
    processPacket(handle, header, pkt_data);
  }
  pcap_close(handle);
  pcap_freealldevs(alldevs);
}
