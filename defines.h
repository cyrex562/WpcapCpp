#pragma once

#define MAC_ADDR_LEN 6
#define ETH_HDR_LEN 14
#define IPV4_HDR_LEN 20
#define PCAP_ERR_BUF_SZ 256

#define AF_UNSPEC 0
#define AF_UNIX 1 // Unix domain sockets
#define AF_INET 2 // IPv4
#define AF_INET6 10 // IPv6
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK
#define AF_PACKET // packet family
#define AF_LLC 26 // linux LLC
#define AF_BLUETOOTH 31
#define AF_BRIDGE 7 // multi-proto bridge


