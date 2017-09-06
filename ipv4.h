#pragma once

struct IPOptionSpec {
    //    u8 option: 7;
    //    u8 optClass : 2;
    //    u8 cpyFlag : 1;
    uint8_t cpyFlag : 1;
    uint8_t optClass : 2;
    uint8_t option : 7;
};


struct IPV4Address {
    union {
        uint32_t i;
        uint8_t b[4];
    };
};

enum IPProtoNum {
    IPPHOPOT = 0,
    IPPICMP = 1,
    IPPIGMP = 2,
    IPPIPV4Encap = 4,
    IPPST = 5,
    IPPTCP = 6,
    IPPEGP = 8,
    IPPIGP = 9,
    IPPUDP = 17,
    IPPDCCP = 33,
    IPPIPV6Encap = 41,
    IPPIPv6Route = 43,
    IPPIPv6Frag = 44,
    IPPGRE = 47,
    IPPESP = 50,
    IPPAH = 51,
    IPPIPV6ICMP = 58,
    IPPIPV6NoNext = 59,
    IPPIPV6DestOpts = 60,
    IPPEIGRP = 88,
    IPPIPIP = 94,
    IPPPIM = 103,
    IPPIPComp = 108,
    IPPSCTP = 132,


};

struct ipv4Header {
    // Little Endian
    // IHL = number of dwords in header
    uint8_t intHdrLen : 4;
    uint8_t version : 4;
    uint8_t dffSvcCodePoint : 6;
    uint8_t expCongestNotif : 2;
    // packet size including IP header
    uint16_t totalLength;
    // IP ID
    uint16_t ident;
    // fragment data
    uint16_t fragOff : 13;
    uint16_t flags : 3;
    // time-to-live
    uint8_t timeToLive;
    // IP protocol number
    uint8_t proto;
    // IP header checksum
    uint16_t checksum;
    struct IPV4Address srcAddr;
    struct IPV4Address dstAddr;
};

char* ipv4AddrToStr(IPV4Address* addr);

void processIPFrame(const uint8_t* pktData, uint32_t ptr);