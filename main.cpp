#define _WINSOCKAPI_
#include <cstdint>
#include <cstdarg>
#include <windows.h>
#include <pcap.h>

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

#define MAC_ADDR_LEN 6
#define ETH_HDR_LEN 14
#define IPV4_HDR_LEN 20

// pcap_findalldevs
typedef int (*PPCAPFindAllDevs)(pcap_if_t **, char *);
// void	pcap_freealldevs(pcap_if_t *);
typedef void (*PFreeAllDevs)(pcap_if_t*);
// pcap_t	*pcap_open_live(const char *, int, int, int, char *);
typedef pcap_t* (*PPCAPOpen)(const char *, int, int, int, struct pcap_rmtauth *, char *);
// int 	pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
typedef int (*PPCAPNextEx)(pcap_t*, struct pcap_pkthdr **, const u_char **);

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

// data structures
struct EthernetAddress {
    u8 addr[6];
};

struct EthernetHeader {
    struct EthernetAddress srcMacAddr;
    struct EthernetAddress dstMacAddr;
    u16 etherTypeNO;
};

struct IPV4Address {
    union {
        u32 i;
        u8 b[4];
    };
};

struct ipv4Header {
    u8 IHL: 4, version: 4;
    u8 DSCP : 6, ECN: 2;
    u16 totLenNO;
    u16 IdentNO;
    u16 fragOffNO : 13, flagsNO : 3;
    u8 TTL;
    u8 proto;
    u16 hdrCsumNO;
    struct IPV4Address srcAddr;
    struct IPV4Address dstAddr;
};

struct TCPHeader {
    u16 srcPort;
    u16 dstPort;
    u32 seqNum;
    u32 ackNum;
    u16 res1 : 4;
    u16 doff : 4;
    u16 fin : 1;
    u16 syn : 1;
    u16 rst : 1;
    u16 psh : 1;
    u16 ack : 1;
    u16 urg : 1;
    u16 res2 : 2;
    u16 winSz;
    u16 csum;
    u16 urgPtr;
};

struct UDPHeader {
    u16 srcPort;
    u16 dstPort;
    u16 len;
    u16 csum;
};

struct ARPHeader {
    u16 hType;
    u16 pType;
    u8 hLen;
    u8 pLen;
    u16 operation;
    EthernetAddress sndHWAddr;
    IPV4Address sndProtoAddr;
    EthernetAddress tgtHWAddr;
    IPV4Address tgtProtoAddr;
};

struct IPOptionSpec {
//    u8 option: 7;
//    u8 optClass : 2;
//    u8 cpyFlag : 1;
    u8 cpyFlag : 1;
    u8 optClass : 2;
    u8 option : 7;
};

enum LogLevel {
    debug,
    info,
    notification,
    warning,
    error
};

u32 _ntohl(u32 in32);
u32 prolog();
char* etherAddrToStr(EthernetAddress* etherAddrBytes);
char* ipv4AddrToStr(IPV4Address* addr);
u16 _ntohs(u16 in16);
u32 _ntohl(u32 in32);
void log(LogLevel level, const char *fmt, ...);

HMODULE hLib;

void log(LogLevel level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    auto output = stdout;
    if (level == error || level == warning) {
        output = stderr;
    }

    vfprintf(output, fmt, args);
    va_end(args);
}

u32 prolog() {
    if (hLib != NULL) {
        FreeLibrary(hLib);
    }
    return 0;
}

char* etherAddrToStr(EthernetAddress* etherAddrBytes) {
    // XX:XX:XX:XX:XX:XX
    static char etherAddrStr[19] = { 0 };
    sprintf(etherAddrStr, "%02x:%02x:%02x:%02x:%02x:%02x",
        etherAddrBytes->addr[0],
        etherAddrBytes->addr[1],
        etherAddrBytes->addr[2],
        etherAddrBytes->addr[3],
        etherAddrBytes->addr[4],
        etherAddrBytes->addr[5]);
    return etherAddrStr;
}

char* ipv4AddrToStr(IPV4Address* inAddr) {
    // XXX.XXX.XXX.XXX
    IPV4Address addrHO = {};
    static char ipv4AddrStr[16] = { 0 };
//    addrHO.i = _ntohl(inAddr->i);

/*
    sprintf(ipv4AddrStr, "%hhu.%hhu.%hhu.%hhu",
        addrHO.b[3],
        addrHO.b[2],
        addrHO.b[1],
        addrHO.b[0]);
*/
    sprintf(ipv4AddrStr, "%hhu.%hhu.%hhu.%hhu",
        inAddr->b[0],
        inAddr->b[1],
        inAddr->b[2],
        inAddr->b[3]);

    return ipv4AddrStr;
}

u16 _ntohs(u16 in16) {
    u8 data[2] = {};
    memcpy(&data, &in16, sizeof(data));
    return ((u16)data[1] << 0) | ((u16)data[0] << 8);
}

u32 _ntohl(u32 in32) {
    u8 data[4] = {};
    memcpy(&data, &in32, sizeof(data));
    return ((u32)data[3] << 0) 
    | ((u32)data[2] << 8) 
    | ((u32)data[1] << 16) 
    | ((u32)data[0] << 24);
}

int main()
{
    printf("loading library\n");
    hLib = LoadLibrary("wpcap.dll");
    if (hLib == NULL) {
        printf("failed to load library wpcap.dll\n");
        return -1;
    }

    printf("getting proc addrs\n");
    PPCAPFindAllDevs pcapFindAllDevs = (PPCAPFindAllDevs)GetProcAddress(hLib, "pcap_findalldevs");
    if (pcapFindAllDevs == NULL) {
        printf("failed to get proc addr for pcap_findalldevs\n");
        prolog();
        return -1;
    }

    PFreeAllDevs pcapFreeAllDevs = (PFreeAllDevs)GetProcAddress(hLib, "pcap_freealldevs");
    if (pcapFreeAllDevs == NULL) {
        printf("failed to get proc addr for pcap_freealldevs\n");
        prolog();
        return -1;
    }

    PPCAPOpen pcapOpen = (PPCAPOpen)GetProcAddress(hLib, "pcap_open");
    if (pcapOpen == NULL) {
        printf("failed to get proc addr for pcap_open_live\n");
        prolog();
        return -1;
    }

    PPCAPNextEx pcapNextEx = (PPCAPNextEx)GetProcAddress(hLib, "pcap_next_ex");
    if (pcapNextEx == NULL) {
        printf("failed to get proc addr for pcap_next_ex\n");
        prolog();
        return -1;
    }

    pcap_if_t *allDevs;
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    printf("getting list of devices\n");
    auto result = pcapFindAllDevs(&allDevs, errBuf);
    if (result == -1) {
        printf("error calling pcap_findalldevs: %s\n", errBuf);
        prolog();
        return -1;
    }

    auto i = 0;
    auto iface_cnt = 0;
    pcap_if_t* interfaces[64] = {0};
    for (pcap_if_t *dev = allDevs; dev; dev = dev->next) {
        printf("%d: name: \"%s\" ", ++i, dev->name);
        iface_cnt++;
        printf("desc: ");
        if (dev->description) {
            printf("\"%s\"\n", dev->description);
        } else {
            printf("none\n");
        }
        interfaces[i] = dev;
        if (dev->addresses) {
            for (pcap_addr *addr = dev->addresses; addr; addr = addr->next) {
                printf("\taddresses: ");
                printf("src_addr: ");
                if (addr->addr && addr->addr->sa_family == AF_INET) {
                    printf("%hhu.%hhu.%hhu.%hhu ", addr->addr->sa_data[0],
                           addr->addr->sa_data[1], addr->addr->sa_data[2],
                           addr->addr->sa_data[3]);
                } else {
                    printf("none ");
                }
                printf("dst_addr: ");
                if (addr->dstaddr && addr->dstaddr->sa_family == AF_INET) {
                    printf("%hhu.%hhu.%hhu.%hhu ", addr->dstaddr->sa_data[0],
                           addr->dstaddr->sa_data[1], addr->dstaddr->sa_data[2],
                           addr->dstaddr->sa_data[3]);
                } else {
                    printf("none ");
                }
                printf("bcast: ");
                if (addr->broadaddr && addr->broadaddr->sa_family == AF_INET) {
                    printf("%hhu.%hhu.%hhu.%hhu ", addr->broadaddr->sa_data[0],
                           addr->broadaddr->sa_data[1],
                           addr->broadaddr->sa_data[2],
                           addr->broadaddr->sa_data[3]);
                } else {
                    printf("none ");
                }
                printf("mask: ");
                if (addr->netmask && addr->netmask->sa_family == AF_INET) {
                    printf("%hhu.%hhu.%hhu.%hhu ", addr->netmask->sa_data[0],
                           addr->netmask->sa_data[1],
                           addr->netmask->sa_data[2],
                           addr->netmask->sa_data[3]);
                } else {
                    printf("none ");
                }
                printf("\n");
            }
        } else {
            printf("none\n");
        }
    }

    auto choice = 0;
    scanf("%u", &choice);



    if (choice <= 0 || choice > ARRAYSIZE(interfaces)) {
        printf("invalid interface choice\n");
        prolog();
        return -1;
    }

    memset(errBuf, 0, PCAP_ERRBUF_SIZE);
    pcap_t *pcapHandle = NULL;

    char fullName[0xffff] = {0};
    strcat(fullName, "rpcap://");
    strcat(fullName, interfaces[choice]->name);

    pcapHandle = pcapOpen(fullName,
                          65535,
                          1,
                          1000,
                          NULL,
                          errBuf);
    if (pcapHandle == NULL) {
        printf("pcapOpen failed: %s\n", errBuf);
        prolog();
        return -1;
    }

    result = 0;
    struct pcap_pkthdr *pktHdr;
    const unsigned char *pktData;
    while (true) {
        result =  pcapNextEx(pcapHandle,
                             &pktHdr,
                             &pktData);
        if (result == 0) {
            printf("timeout ocurred\n");
        } else if (result == -1) {
            printf("error occurred\n");
            prolog();
            return -1;
        } else if (result == -2) {
            printf("EOF occurred\n");
            break;
        }
        else if (result == 1) {
            printf("packet captured\n");
            UINT ptr = 0;
            struct EthernetHeader *ethHdr = (struct EthernetHeader *)(&pktData[ptr]);
            ptr += ETH_HDR_LEN;
            UINT8 *ethPayload = (UINT8*)&pktData[ptr];
            size_t ethPayloadLen = pktHdr->caplen - ETH_HDR_LEN;
            
            printf("src mac addr: %s ", etherAddrToStr(&ethHdr->srcMacAddr));
            printf("dst mac addr: %s ", etherAddrToStr(&ethHdr->dstMacAddr));
            UINT16 etherType = _ntohs(ethHdr->etherTypeNO);
            printf("ether Type: %04x (%hu)\n", etherType, etherType);

            if (etherType < 1500 ) {
                printf("packet is not ethernet II\n");
            } else if (etherType >= 1536) {
                printf("packet is ethernet II\n");
                if (etherType == 0x0800) {
                    printf("next header is IPv4\n");
                    struct ipv4Header* ipHdr = (struct ipv4Header*)&pktData[ptr];
                    if (ipHdr-> IHL > 5) {
                        printf("IP header has options\n");
                        auto optPtr = ptr + IPV4_HDR_LEN;
                        auto optBytes = (ipHdr->IHL * 4) - IPV4_HDR_LEN;
                        struct IPOptionSpec* optSpec = (struct IPOptionSpec*)&pktData[optPtr];
                        printf("option: %hhu ", optSpec->option);
                        if (optSpec->option == 4) {
                            printf(" IP time stamp\n");
                        } else {
                            printf(" Unhandled IP Option\n");
                        }

                    }
                    ptr += ipHdr->IHL * 4;
                    printf("src addr: %s ", ipv4AddrToStr(&ipHdr->srcAddr));
                    printf("dst addr: %s ", ipv4AddrToStr(&ipHdr->dstAddr));
                    printf("proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
                    if (ipHdr->proto == 6) {
                        printf("tcp header follows\n");
                        struct TCPHeader* tcpHdr = (struct TCPHeader*)&pktData[ptr];
                        auto dstPort = _ntohs(tcpHdr->dstPort);
                        auto srcPort = _ntohs(tcpHdr->srcPort);
                        printf("src port: %hu", srcPort);
                        printf(", dst port: %hu", dstPort);
                        printf(", data offset: %hu", tcpHdr->doff);
                        printf(", flags: FIN: %hhu, SYN: %hhu, RST: %hhu, PSH: %hhu, ACK: %hhu, URG: %hhu", tcpHdr->fin, tcpHdr->syn, tcpHdr->rst, tcpHdr->psh, tcpHdr->ack, tcpHdr->urg);
                        if (dstPort == 5222 || srcPort == 5222) {
                            printf(", app proto is XMPP\n");
                        } else {
                            printf(", unhandled app proto\n");
                        }
                    } else if (ipHdr->proto == 2) {
                        printf("IGMP header follows\n");
                    } else if (ipHdr->proto == 17) {
                        printf("UDP header follows\n");
                        struct UDPHeader* udpHdr = (struct UDPHeader*)&pktData[ptr];
                        printf("src port: %hu ", _ntohs(udpHdr->srcPort));
                        printf("dst port: %hu ", _ntohs(udpHdr->dstPort));
                        printf("len: %hu", udpHdr->len);
                    } else {
                        printf("unhandled IP proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
                    }
                } else if (etherType == 0x0806) {
                    printf("next header is ARP\n");
                    auto arpHdr = (struct ARPHeader*)&pktData[ptr];
                    printf("htype: %04x ", arpHdr->hType);
                    printf("ptype: %04x ", arpHdr->pType);
                    printf("hLen: %02x ", arpHdr->hLen);
                    printf("pLen: %02x ", arpHdr->pLen);
                    printf("oper: %04x ", arpHdr->operation);
                    printf("SHA: %s ", etherAddrToStr(&arpHdr->sndHWAddr));
                    printf("SPA: %s ", ipv4AddrToStr(&arpHdr->sndProtoAddr));
                    printf("THA: %s ", etherAddrToStr(&arpHdr->tgtHWAddr));
                    printf("TPA: %s ", ipv4AddrToStr(&arpHdr->tgtProtoAddr));
                } else if (etherType == 0x86dd) {
                    printf("next header is IPV6\n");
                } else {
                    printf("unhandled etherType: %hu\n", etherType);
                }
            } else {
                printf("invalid etherType: %hu\n", etherType);
            }
        } else {
            printf("invalid result: %u\n", result);
            prolog();
            return -1;
        }
    }

    prolog();
    return 0;
}
