#define _WINSOCKAPI_
#include <cstdint>
#include <cstdarg>
#include <windows.h>
#include <cstdio>
//#include <pcap.h>

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

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

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;


typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;
typedef struct pcap_rmtauth pcap_rmtauth_t;
typedef u16 sa_family_t;

// pcap_findalldevs
typedef int (*PPCAPFindAllDevs)(pcap_if_t**, char*);
// void	pcap_freealldevs(pcap_if_t *);
typedef void (*PFreeAllDevs)(pcap_if_t*);
// pcap_t	*pcap_open_live(const char *, int, int, int, char *);
typedef pcap_t* (*PPCAPOpen)(const char*, int, int, int, struct pcap_rmtauth*, char*);
// int 	pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
typedef int (*PPCAPNextEx)(pcap_t*, struct pcap_pkthdr**, const u8**);


// data structures
struct pcap_rmtauth {
	int type;
	char* username;
	char* password;
};

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
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
	u32 flags;
};

/*
 * http://www.networksorcery.com/enp/protocol/802/ethertypes.htm
 */
enum EtherType {
	// 0x0000 - 0x05DC IEEE 802.3 Length
	ETypeIP = 0x0800,
	ETypeARP = 0x0806,
	ETypeSNMP = 0x814C,
	ETypeIPV6 = 0x86DD,
	ETypePPP = 0x880B,
	ETypeMPLSUC = 0x8847,
	ETypeMPLSMC = 0x8848,
	ETypePPPoEDisc = 0x8863,
	ETypePPPoESession = 0x8864,
	ETypeATAoE = 0x88A2,
	ETypeLLDP = 0x88CC,
	ETypeReserved = 0xFFFF
};

enum LSAPValue {
	LSAPNull = 0,
	LSAPIndivLLCSubMgmt = 2,
	LSAPGrpLLCSubMgmt = 3,
	LSAP8021BrSTP = 0x42,
	LSASNAP = 0xAA,
	LSAGlobalDSAP = 0xFF
};

struct EthernetAddress {
	u8 addr[6];
};

/*
 * http://www.networksorcery.com/enp/protocol/ethernet.htm
 */
struct EthernetHeader {
	struct EthernetAddress srcMacAddr;
	struct EthernetAddress dstMacAddr;
	u16 etherTypeNO;
};

/*
 *  https://en.wikipedia.org/wiki/IEEE_802.2#cite_note-LAN_tech-3
 *  http://www.networksorcery.com/enp/protocol/IEEE8022.htm
 */
struct LLCHeader {
	u8 DSAPAddr;
	u8 SSAPAddr;
	u8 control;
};

/*
 * https://en.wikipedia.org/wiki/Spanning_Tree_Protocol#Bridge_Protocol_Data_Units
 */
struct BridgePDU {
	// 0x0000 for 802.1d
	u16 protocolID;
	// 0x00: config & tcn; 0x02: RST; 0x03: MST; 0x04: SPT
	u8 versionID;
	// 0x00: STP; 0x80: TCN BPDU; 0x02: RST/MST config BPDU
	u8 bpduType;
	/*
	 bits  : usage
	   1 : 0 or 1 for Topology Change
	   2 : 0 (unused) or 1 for Proposal in RST/MST/SPT BPDU
	 3-4 : 00 (unused) or
		   01 for Port Role Alternate/Backup in RST/MST/SPT BPDU
		   10 for Port Role Root in RST/MST/SPT BPDU
		   11 for Port Role Designated in RST/MST/SPT BPDU
	   5 : 0 (unused) or 1 for Learning in RST/MST/SPT BPDU
	   6 : 0 (unused) or 1 for Forwarding in RST/MST/SPT BPDU
	   7 : 0 (unused) or 1 for Agreement in RST/MST/SPT BPDU
	   8 : 0 or 1 for Topology Change Acknowledgement
	 */
	u8 flags;
	/*
	 * Root ID:
	 * 1-4 : Root Bridge Priority
	5-16 : Root Bridge System ID Extension
   17-64 : Root Bridge MAC Address
	 */
	u8 rootID[8];
	// CIST Ext Path cost in MST/SPT BPDU
	u32 rootPathCost;
	/* Bridge ID:
	 * bits  : usage
	 1-4 : Bridge Priority
	5-16 : Bridge System ID Extension
   17-64 : Bridge MAC Address
	 */
	u8 bridgeID[8];
	u16 portID;
	// units: 1/256 secs
	u16 messageAge;
	u16 maxAge;
	u16 helloTime;
	u16 fwdDelay;
	// 0x00: no ver 1 info present; RST, MST, SPT BPDU only
	u8 vers1Length;
	// MST, SPT BPDU only
	u16 vers3Length;
};

struct IPV4Address {
	union {
		u32 i;
		u8 b[4];
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
	u8 IHL : 4, version : 4;
	u8 DSCP : 6, ECN : 2;
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

struct timeval {
	long tv_sec;
	long tv_usec;
};

struct pcap_pkthdr {
	struct timeval ts; /* time stamp */
	u32 caplen; /* length of portion present */
	u32 len; /* length this packet (off wire) */
};

/**/
enum IGMPType {
	createGrpReq = 1,
	createGrpReply = 2,
	joinGrpReq = 3,
	joinGrpReply = 4,
	leaveGrpReq = 5,
	leaveGrpReply = 6,
	confirmGrpReq = 7,
	configmrGrpReply = 8
};

enum IGMPCode {
	reqPublic = 0,
	reqPrivate = 1,
	reqGranted = 0,
	reqDeniedNoResc = 1,
	reqDeniedInvalidCode = 2,
	reqDeniedInvalidGrpAddr = 3,
	reqDeniedInvalidKey = 4
	// if the value is greater than 5 it indicates a request pending with a retry timeout.
};

struct IGMPHeader {
	u8 type;
	u8 code;
	u16 checksum;
	/* all zero in confirm group request; all other request contains a value to distinguish the request for the host; in replies contains the same value as the corresponding request. */
	u32 identifier;
	/* all zeros in create group request; all other requests: contains a host group address; create group reply: newly allocated host group addr or zero if denied; all other replies: contains the same host group address as the corresponding request. */
	u32 groupAddress;
	/*
	 * create group req: all zero
	 * other requests: contains access key assigned to the host group
	 * create group reply: non-zero 64-bit num or zero if denied;
	 * other replies: same access key as the corresponding request.
	 */
	u64 accessKey;
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
void log(LogLevel level, const char* fmt, ...);

HMODULE hLib;

void log(LogLevel level, const char* fmt, ...) {
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
	static char etherAddrStr[19] = {0};
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
	static char ipv4AddrStr[16] = {0};
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

void printBytes(u8* bytes, size_t count) {
	printf("addr: %p, count: %z, bytes[ ", bytes, count);
	for (int i = 0; i < count; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("]\n");
}

void processLLCFrame(const unsigned char* pktData, UINT& ptr) {
	LLCHeader* llcHdr = (LLCHeader*)(&pktData[ptr]);
	if (llcHdr->DSAPAddr == LSAP8021BrSTP || llcHdr->SSAPAddr == LSAP8021BrSTP) {
		ptr += 3;
		BridgePDU* stpHdr = (BridgePDU*)(&pktData[ptr]);
		printf("LLC frame is a STP BPDU\n");
	} else {
		printf("unhandled LLC frame type\n");
	}
}

void processNetworkInterfaces(pcap_if_t* allDevs, pcap_if_t*(& interfaces)[64]) {
	auto i = 0;
	auto iface_cnt = 0;
	
	for (pcap_if_t* dev = allDevs; dev; dev = dev->next) {
		printf("%d: name: \"%s\" ", ++i, dev->name);
		iface_cnt++;
		printf("desc: ");
		if (dev->description) {
			printf("\"%s\"\n", dev->description);
		}
		else {
			printf("none\n");
		}
		interfaces[i] = dev;
		if (dev->addresses) {
			for (pcap_addr* addr = dev->addresses; addr; addr = addr->next) {
				printf("\taddresses: ");
				printf("src_addr: ");
				if (addr->addr && addr->addr->sa_family == AF_INET) {
					printf("%hhu.%hhu.%hhu.%hhu ", 
					       addr->addr->sa_data[2],
					       addr->addr->sa_data[3], 
					       addr->addr->sa_data[1],
					       addr->addr->sa_data[0]);
				}
				else {
					printf("none ");
				}
				printf("dst_addr: ");
				if (addr->dstaddr && addr->dstaddr->sa_family == AF_INET) {
					printf("%hhu.%hhu.%hhu.%hhu ", 
					       addr->dstaddr->sa_data[2],
					       addr->dstaddr->sa_data[3], 
					       addr->dstaddr->sa_data[1],
					       addr->dstaddr->sa_data[0]);
				}
				else {
					printf("none ");
				}
				printf("bcast: ");
				if (addr->broadaddr && addr->broadaddr->sa_family == AF_INET) {
					printf("%hhu.%hhu.%hhu.%hhu ", 
					       addr->broadaddr->sa_data[2],
					       addr->broadaddr->sa_data[3],
					       addr->broadaddr->sa_data[1],
					       addr->broadaddr->sa_data[0]);
				}
				else {
					printf("none ");
				}
				printf("mask: ");
				if (addr->netmask && addr->netmask->sa_family == AF_INET) {
					printf("%hhu.%hhu.%hhu.%hhu ", 
					       addr->netmask->sa_data[2],
					       addr->netmask->sa_data[3],
					       addr->netmask->sa_data[1],
					       addr->netmask->sa_data[0]);
				}
				else {
					printf("none ");
				}
				printf("\n");
			}
		}
		else {
			printf("none\n");
		}
	}
}

void processIGMPFrame(const unsigned char* pktData, UINT& ptr) {
	struct IGMPHeader* igmpHdr = (struct IGMPHeader*)&pktData[ptr];
	printf("type: %hhu ", igmpHdr->type);
	printf("code: %hhu ", igmpHdr->code);
	printf("identifier: %08x ", igmpHdr->identifier);
	printf("groupAddress: %08x ", igmpHdr->groupAddress);
	printf("accessKey: %016x\n", igmpHdr->accessKey);
}

void processUDPFrame(const unsigned char* pktData, UINT& ptr) {
	struct UDPHeader* udpHdr = (struct UDPHeader*)&pktData[ptr];
	u16 srcPort = _ntohs(udpHdr->srcPort);
	u16 dstPort = _ntohs(udpHdr->dstPort);
	ptr += 8;
	u8* udpPayload = (u8*)(&pktData[ptr]);
	size_t payloadLength = (size_t)(_ntohs(udpHdr->len));
	printf("udp header: ");
	printf("src port: %hu ", srcPort);
	printf("dst port: %hu ", dstPort);
	printf("len: %hu\n", payloadLength);
	if (srcPort == 5353 || dstPort == 5353) {
		printf("MDNS header follows\n");
		// TODO: implement multicast header parsing
	}
	else if (srcPort == 1900 || dstPort == 1900) {
		printf("SSDP frame follows\n");
		// TODO: implement SSDP frame parsing.
	}
	else if (srcPort == 137 || dstPort == 137) {
		printf("netbios name service frame follows\n");
	}
	else if (srcPort == 138 || dstPort == 138) {
		printf("netbios data gram service frame follows\n");
	}
	else if (dstPort == 49153) {
		printf("temperature sensor\n");
	}
	else if (srcPort == 5355 || dstPort == 5355) {
		printf("LLMNR frame follows\n");
	}
	else if (srcPort == 53 || dstPort == 53) {
		printf("DNS frame follows\n");
	}
	else if (srcPort == 123 || dstPort == 123) {
		printf("NTP frame follows\n");
	}
	else if (srcPort == 3702 || dstPort == 3702) {
		printf("ws-discovery frame follows\n");
	}
	else if (dstPort == 67 || srcPort == 67 || dstPort == 68 || srcPort == 68) {
		printf("DHCP frame follows\n");
	}
	else if (dstPort > 49152) {
		printf("ephemeral or unassigned destination port %hu\n", dstPort);
		printBytes(udpPayload, payloadLength);
	}
	
	else {
		printf("unhandled port number: src: %hu, dst: %hu\n", srcPort, dstPort);
		printBytes(udpPayload, payloadLength);
	}
	
}

void processTCPFrame(const unsigned char* pktData, UINT& ptr) {
	struct TCPHeader* tcpHdr = (struct TCPHeader*)&pktData[ptr];
	auto dstPort = _ntohs(tcpHdr->dstPort);
	auto srcPort = _ntohs(tcpHdr->srcPort);
	printf("src port: %hu", srcPort);
	printf(", dst port: %hu", dstPort);
	printf(", data offset: %hu", tcpHdr->doff);
	printf(", flags: FIN: %hhu, SYN: %hhu, RST: %hhu, PSH: %hhu, ACK: %hhu, URG: %hhu", tcpHdr->fin, tcpHdr->syn, tcpHdr->rst, tcpHdr->psh, tcpHdr->ack, tcpHdr->urg);
	if (dstPort == 5222 || srcPort == 5222) {
		printf(", app proto is XMPP\n");
		// TODO: parse XMPP
	}
	else {
		printf(", unhandled app proto\n");
	}
}

void processIPFrame(const unsigned char* pktData, UINT& ptr) {
	printf("next header is IPv4\n");
	struct ipv4Header* ipHdr = (struct ipv4Header*)&pktData[ptr];
	if (ipHdr->IHL > 5) {
		printf("IP header has options\n");
		auto optPtr = ptr + IPV4_HDR_LEN;
		auto optBytes = (ipHdr->IHL * 4) - IPV4_HDR_LEN;
		struct IPOptionSpec* optSpec = (struct IPOptionSpec*)&pktData[optPtr];
		printf("option: %hhu ", optSpec->option);
		if (optSpec->option == 4) {
			printf(" IP time stamp\n");
		}
		else {
			printf(" Unhandled IP Option\n");
		}

	}
	ptr += ipHdr->IHL * 4;
	printf("src addr: %s ", ipv4AddrToStr(&ipHdr->srcAddr));
	printf("dst addr: %s ", ipv4AddrToStr(&ipHdr->dstAddr));
	printf("proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
	if (ipHdr->proto == 6) {
		printf("tcp header follows\n");
		processTCPFrame(pktData, ptr);
	}
	else if (ipHdr->proto == 2) {
		printf("IGMP header follows\n");
		processIGMPFrame(pktData, ptr);
	}
	else if (ipHdr->proto == IPPUDP) {
		printf("UDP header follows\n");
		processUDPFrame(pktData, ptr);
	}
	else if (ipHdr->proto = IPPPIM) {
		printf("PIM header follows\n");
		// TODO: implement PIM header parsing.
	}
	else {
		printf("unhandled IP proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
	}
}

void processARPFrame(const unsigned char* pktData, UINT ptr) {
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
}

int main() {
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

	pcap_if_t* allDevs;
	char errBuf[PCAP_ERR_BUF_SZ] = {0};
	printf("getting list of devices\n");
	auto result = pcapFindAllDevs(&allDevs, errBuf);
	if (result == -1) {
		printf("error calling pcap_findalldevs: %s\n", errBuf);
		prolog();
		return -1;
	}

	pcap_if_t* interfaces[64] = {0};
	processNetworkInterfaces(allDevs, interfaces);

	// get user selection for interface
	auto choice = 0;
	scanf("%u", &choice);
	if (choice <= 0 || choice > ARRAYSIZE(interfaces)) {
		printf("invalid interface choice\n");
		prolog();
		return -1;
	}

	memset(errBuf, 0, PCAP_ERR_BUF_SZ);
	pcap_t* pcapHandle = NULL;
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

	struct pcap_pkthdr* pktHdr;
	const unsigned char* pktData;
	while (true) {
		result = pcapNextEx(pcapHandle,
		                    &pktHdr,
		                    &pktData);
		if (result == 0) {
			printf("timeout ocurred\n");
		}
		else if (result == -1) {
			printf("error occurred\n");
			prolog();
			return -1;
		}
		else if (result == -2) {
			printf("EOF occurred\n");
			break;
		}
		else if (result == 1) {
			printf("packet captured\n");
			UINT ptr = 0;
			
			struct EthernetHeader* ethHdr = (struct EthernetHeader *)(&pktData[ptr]);
			ptr += ETH_HDR_LEN;
			u8* ethPayload = (u8*)&pktData[ptr];
			size_t ethPayloadLen = pktHdr->caplen - ETH_HDR_LEN;

			printf("src mac addr: %s ", etherAddrToStr(&ethHdr->srcMacAddr));
			printf("dst mac addr: %s ", etherAddrToStr(&ethHdr->dstMacAddr));
			u16 etherType = _ntohs(ethHdr->etherTypeNO);
			printf("ether Type: %04x (%hu)\n", etherType, etherType);

			if (etherType < 1500) {
				printf("packet is not ethernet II\n");
				printBytes(ethPayload, ethPayloadLen);
				processLLCFrame(pktData, ptr);
			}
			else if (etherType >= 1536) {
				printf("packet is ethernet II\n");
				if (etherType == ETypeIP) {
					processIPFrame(pktData, ptr);
				}
				else if (etherType == ETypeARP) {
					processARPFrame(pktData, ptr);
				}
				else if (etherType == ETypeIPV6) {
					printf("next header is IPV6\n");
					// TODO: implement IPV6 parsing
				}
				else if (etherType == ETypeLLDP) {
					printf("next header is LLDP\n");
					// TODO: implement LLDP parsing
				} 
				else if (etherType == 0x9104) {
					printf("anomalous ether type 0x9104\n");
					printBytes(ethPayload, ethPayloadLen);
				}
				else {
					printf("unhandled etherType: %hu\n", etherType);
					printBytes(ethPayload, ethPayloadLen);
				}
			}
			else {
				printf("invalid etherType: %hu\n", etherType);
			}
		}
		else {
			printf("invalid result: %u\n", result);
			prolog();
			return -1;
		}
	}

	prolog();
	return 0;
}
