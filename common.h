#pragma once

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

#include <libnet/config.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
