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

#define RING_BUF_SZ 256

#ifdef __ANDROID__
#define ANDROID 1
#endif

#ifdef __linux__
#define LINUX 1
#endif

#ifdef _WIN32
#define WIN32 1
#endif

#ifdef _WIN64
#define WIN64 1
#endif

#ifdef __amd64__ || __x86_64__ || _M_AMD64
#define X64 1
#endif

#ifdef __arm__ || __thumb__ || _M_ARM || _M_ARMT
#define ARM 1
#endif

#ifdef _M_IX86 || _M_IX86 || _X86_ || __i386__
#define X86 1
#endif


/*
 * Big endian	    __BYTE_ORDER	__BIG_ENDIAN
 * Little endian    __BYTE_ORDER	__LITTLE_ENDIAN
 */

typedef uint16_t sa_family_t;

enum {
    EndianUnkown,
    EndianBig,
    EndianLittle
};


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



