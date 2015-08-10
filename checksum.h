#pragma once

#include "common.h"

uint16_t ipChecksum(libnet_ipv4_hdr* ipHdr);
uint16_t tcpChecksum(libnet_ipv4_hdr* ipHdr, libnet_tcp_hdr* tcpHdr);
