#pragma once

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;
typedef struct pcap_rmtauth pcap_rmtauth_t;


// pcap_findalldevs
typedef int(*PPCAPFindAllDevs)(pcap_if_t**, char*);
// void	pcap_freealldevs(pcap_if_t *);
typedef void(*PFreeAllDevs)(pcap_if_t*);
// pcap_t	*pcap_open_live(const char *, int, int, int, char *);
typedef pcap_t* (*PPCAPOpen)(const char*, int, int, int, struct pcap_rmtauth*, char*);
// int 	pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
typedef int(*PPCAPNextEx)(pcap_t*, struct pcap_pkthdr**, const uint8_t**);



struct pcap_pkthdr {
    struct timeval ts; /* time stamp */
    uint32_t caplen; /* length of portion present */
    uint32_t len; /* length this packet (off wire) */
};

// data structures
struct pcap_rmtauth {
    int type;
    char* username;
    char* password;
};



struct pcap_addr {
    struct pcap_addr* next;
    struct sockaddr* addr; /* address */
    struct sockaddr* netmask; /* netmask for that address */
    struct sockaddr* broadaddr; /* broadcast address for that address */
    struct sockaddr* dstaddr; /* P2P destination address for that address */
};

struct pcap_if {
    struct pcap_if* next;
    char* name;
    char* description;
    struct pcap_addr* addresses;
    uint32_t flags;
};

extern PPCAPFindAllDevs pcapFindAllDevs;
extern PFreeAllDevs pcapFreeAllDevs;
extern PPCAPOpen pcapOpen;
extern PPCAPNextEx pcapNextEx;

Result processNetworkInterfaces(char **ifaceName);

//Result processPacket(const uint8_t* pktData,
//                     struct pcap_pkthdr* pktHdr);
Result processPacket(PacketRingBuffer* pktRingBuf);
//void initPcap();