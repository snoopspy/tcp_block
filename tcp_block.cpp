#ifdef WIN32
#define  WPCAP
#define  HAVE_REMOTE
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif
#include <pcap.h>
#include <iostream>
#include <stdlib.h>

#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>

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
  if (pcap_compile(handle, &fcode, "tcp and port 80", 1, netmask) < 0)
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

static void processPacket(pcap_if_t* handle, struct pcap_pkthdr* header, const u_char* pkt_data) {
  libnet_ethernet_hdr* ethHdr = (libnet_ethernet_hdr*)pkt_data;
  if (ntohs(ethHdr->ether_type) != ETHERTYPE_IP)
      return;

  libnet_ipv4_hdr* ipHdr = (libnet_ipv4_hdr*)(ethHdr + 1);
  if (ipHdr->ip_p != IPPROTO_TCP)
    return;

  //libnet_tcp_hdr* tcpHdr = (libnet_tcp_hdr*)((u_char*)ipHdr + ipHdr->ip_hl * 4);
  libnet_tcp_hdr* tcpHdr = (libnet_tcp_hdr*)((u_char*)ipHdr + sizeof(libnet_ipv4_hdr));

  std::cout << ntohs(tcpHdr->th_dport) << " " << std::endl;
}

int main() {
  pcap_if_t* d = getDevice();
  if (d == NULL) {
    return -1;
  }

  pcap_t* handle = openDevice(d);
  if (handle == NULL) {
    return -1;
  }

  while (true) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = pcap_next_ex(handle, &header, &pkt_data);
    if (res == 0) continue;
    if (res < 0) break;
    processPacket(d, header, pkt_data);
  }
  pcap_close(handle);
  pcap_freealldevs(alldevs);

}
