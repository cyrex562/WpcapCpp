#pragma once

#include <cstdint>

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

#if defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
#define X64 1
#endif

#if defined(__arm__) || defined(__thumb__) || defined(_M_ARM) || defined(_M_ARMT)
#define ARM 1
#endif

#if defined(_M_IX86) || defined(_M_IX86) || defined(_X86_) || defined(__i386__)
#define X86 1
#endif

#define MAX_LABEL_NUM 0xff

/*
 * Big endian	    __BYTE_ORDER	__BIG_ENDIAN
 * Little endian    __BYTE_ORDER	__LITTLE_ENDIAN
 */

typedef uint16_t SocAddrFamily;

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

enum PacketLabel {
    PLNone,
    PLPCAP,
    PLEthernet,

};

// internal implementation of the Windows/*Nix timeval struct
typedef struct TimeVal {
    long tv_sec;
    long tv_usec;
} TimeVal;

typedef struct sockaddr {
    SocAddrFamily sa_family;
    char sa_data[14];
} SockAddr;

typedef struct PacketInfo {
    TimeVal time_stamp;
    uint32_t packet_length;
    uint8_t data[MAX_PKT_LEN];
    uint16_t data_ptr;
    PacketLabel labels[MAX_LABEL_NUM];
    size_t label_ptr;
} PacketInfo;

typedef struct EthernetAddress {
    uint8_t addr[6];
} EthernetAddress;

typedef struct IPV4Address {
    union {
        uint32_t i;
        uint8_t b[4];
    };
} IPV4Address;

