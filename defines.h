#pragma once

#define MAC_ADDR_LEN 6
#define ETH_HDR_LEN 14
#define IPV4_HDR_LEN 20
#define PCAP_ERR_BUF_SZ 256

#define AF_UNSPEC 0
#define AF_UNIX 1 // Unix domain sockets
#define AF_INET 2 // IPv4
#define AF_INET6 23 // IPv6
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK
#define AF_PACKET 17// packet family
#define AF_NETBIOS 17
#define AF_LLC 26 // linux LLC
#define AF_BLUETOOTH 32
#define AF_BRIDGE 7 // multi-proto bridge

#define NON_ETHER_MAX_LEN 1500
#define ETHER_TYPE_MIN_VAL 1536

enum Result {
    ResSuccess = 0,
    ResError = -1,
    ResNotSet = INT32_MAX
};
