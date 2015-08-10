#include "checksum.h"

//
// All ipHdr field except ipHdr.ip_sum
//
uint16_t ipChecksum(libnet_ipv4_hdr* ipHdr)
{
  int i;
  uint32_t sum;
  uint16_t *p;

  sum = 0;

  // Add ipHdr buffer as array of uint16_t
  p = (uint16_t*)(ipHdr);
  for (i = 0; i < (int)sizeof(libnet_ipv4_hdr) / 2; i++)
  {
    sum += ntohs(*p);
    p++;
  }

  // Do not consider padding because ip header length is always multilpe of 2.

  // Decrease checksum from sum
  sum -= ntohs(ipHdr->ip_sum);

  // Recalculate sum
  while(sum >> 16)
  {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  sum = ~sum;

  return (uint16_t)sum;
}

//
// All tcpHdr field except tcpHdr.th_sum
// All data buffer(padding)
// ipHdr.ip_src, ipHdr.ip_dst, tcpHdrDataLen and IPPROTO_TCP
//
uint16_t tcpChecksum(libnet_ipv4_hdr* ipHdr, libnet_tcp_hdr* tcpHdr)
{
  int i;
  int tcpHdrDataLen;
  uint32_t src, dst;
  uint32_t sum;
  uint16_t *p;

  tcpHdrDataLen = ntohs(ipHdr->ip_len) - sizeof(libnet_ipv4_hdr);
  sum = 0;

  // Add tcpHdr and data buffer as array of UIN16
  p = (uint16_t*)tcpHdr;
  for (i = 0; i < tcpHdrDataLen / 2; i++)
  {
    sum += htons(*p);
    p++;
  }

  // If length is odd, add last data(padding)
  if ((tcpHdrDataLen / 2) * 2 != tcpHdrDataLen)
    sum += (htons(*p) & 0xFF00);

  // Decrease checksum from sum
  sum -= ntohs(tcpHdr->th_sum);

  // Add src address
  src = ntohl(ipHdr->ip_src.s_addr);
  sum += ((src & 0xFFFF0000) >> 16) + (src & 0x0000FFFF);

  // Add dst address
  dst = ntohl(ipHdr->ip_dst.s_addr);
  sum += ((dst & 0xFFFF0000) >> 16) + (dst & 0x0000FFFF);

  // Add extra information
  sum += (uint32_t)(tcpHdrDataLen) + IPPROTO_TCP;

  // Recalculate sum
  while(sum >> 16)
  {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  sum = ~sum;

  return (uint16_t)sum;
}
