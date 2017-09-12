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
#define MAX_PKT_LEN 0xffff

typedef uint16_t sa_family_t;

enum Result {
    ResSuccess = 0,
    ResError = -1,
    ResNotSet = INT32_MAX
};

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct Packet {
    struct timeval timeStamp;
    size_t packetLength;
    uint8_t data[MAX_PKT_LEN];
};