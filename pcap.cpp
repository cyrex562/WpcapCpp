#include <cstdio>
#include <cstdint>
#include <cstring>
#include "defines.h"
#include "utils.h"
#include "ethernet.h"
#include "ip.h"
#include "arp.h"

#include "pcap.h"

#define _CRT_SECURE_NO_WARNINGS 1

//void initPcap() {
//    PPCAPFindAllDevs pcapFindAllDevs = NULL;
//    PFreeAllDevs pcapFreeAllDevs = NULL;
//    PPCAPOpen pcapOpen =  NULL;
//    PPCAPNextEx pcapNextEx = NULL;
//}

extern PPCAPFindAllDevs pcapFindAllDevs = NULL;
extern PFreeAllDevs pcapFreeAllDevs = NULL;
extern PPCAPOpen pcapOpen = NULL;
extern PPCAPNextEx pcapNextEx = NULL;

/*
* Process the network interfaces.
*/
Result processNetworkInterfaces(char **ifaceName) {
    auto i = 0;
    auto iface_cnt = 0;
    pcap_if_t* interfaces[64] = { 0 };
    pcap_if_t* allDevs;
    uint16_t choice = 0;
    
    char errBuf[PCAP_ERR_BUF_SZ] = { 0 };
    log(LLDebug, "getting list of devices\n");
    auto result = pcapFindAllDevs(&allDevs, errBuf);
    if (result == -1) {
        log(LLError, "error calling pcap_findalldevs: %s\n", errBuf);
        return ResError;
    }

    for (pcap_if_t* dev = allDevs; dev; dev = dev->next) {
        log(LLDebug, "%d: name: \"%s\"\n", ++i, dev->name);
        iface_cnt++;
        log(LLDebug, "\tdesc: ");
        if (dev->description) {
            log(LLDebug, "\"%s\"\n", dev->description);
        }
        else {
            log(LLDebug, "none\n");
        }
        interfaces[i] = dev;
        if (dev->addresses) {
            log(LLDebug, "\taddresses: \n");
            for (pcap_addr* addr = dev->addresses; addr; addr = addr->next) {
                log(LLDebug, "\t\taddress: \n");
                if (addr->addr) {
                    log(LLDebug, "\t\t\tsrc_addr: ");
                    if (addr->addr->sa_family == AF_INET) {
                        printf("%hhu.%hhu.%hhu.%hhu\n",
                            addr->addr->sa_data[2],
                            addr->addr->sa_data[3],
                            addr->addr->sa_data[1],
                            addr->addr->sa_data[0]);
                    } else {
                        log(LLWarning, "unhandled AF type: %s\n", addrFamToStr(addr->addr->sa_family));
                    }
                }
                else {
                    log(LLDebug, "\t\t\tsrc_addr: none\n");
                }
                
                if (addr->dstaddr) {
                    log(LLDebug, "\t\t\tdst_addr: ");
                    if (addr->dstaddr->sa_family == AF_INET) {
                        printf("%hhu.%hhu.%hhu.%hhu\n",
                            addr->dstaddr->sa_data[2],
                            addr->dstaddr->sa_data[3],
                            addr->dstaddr->sa_data[1],
                            addr->dstaddr->sa_data[0]);
                    } else {
                        log(LLWarning, "unhandled AF type: %s\n", addrFamToStr(addr->dstaddr->sa_family));
                    }
                }
                else {
                    log(LLDebug, "\t\t\tdst_addr: none \n");
                }
                
                if (addr->broadaddr) {
                    log(LLDebug, "\t\t\tbcast: ");
                    if (addr->broadaddr->sa_family == AF_INET) {
                        printf("%hhu.%hhu.%hhu.%hhu\n",
                            addr->broadaddr->sa_data[2],
                            addr->broadaddr->sa_data[3],
                            addr->broadaddr->sa_data[1],
                            addr->broadaddr->sa_data[0]);
                    } else {
                        log(LLWarning, "unhandled AF type: %s\n", addrFamToStr(addr->broadaddr->sa_family));
                    }
                }
                else {
                    log(LLDebug, "\t\t\tbcast: none ");
                }
                
                if (addr->netmask) {
                    log(LLDebug, "\t\t\tmask: ");
                    if (addr->netmask->sa_family == AF_INET) {
                        printf("%hhu.%hhu.%hhu.%hhu\n",
                            addr->netmask->sa_data[2],
                            addr->netmask->sa_data[3],
                            addr->netmask->sa_data[1],
                            addr->netmask->sa_data[0]);
                    } else {
                        log(LLWarning, "unhandled AF type: %s\n", addrFamToStr(addr->netmask->sa_family));
                    }
                }
                else {
                    log(LLDebug, "mask: none\n");
                }
            }
        }
        else {
            log(LLDebug, "addresses: none\n");
        }
    }

    printf("select an interface to capture traffic from: ");
    scanf("%hu", &choice);
    printf("\n");

    static char _ifaceName[0xffff] = { 0 };
    strcat(_ifaceName, "rpcap://");
    strcat(_ifaceName, interfaces[choice]->name);
    *ifaceName = _ifaceName;

    pcapFreeAllDevs(allDevs);

    return ResSuccess;
}

Result processPacket(const uint8_t* pktData,
    struct pcap_pkthdr* pktHdr) {
    log(LLDebug, "\n\n** PACKET **\n");
    auto ptr = 0;
    auto ethHdr = (struct EthernetHeader *)(&pktData[ptr]);
    ptr += ETH_HDR_LEN;
    auto ethPayload = (uint8_t*)&pktData[ptr];
    auto ethPayloadLen = (size_t)(pktHdr->caplen - ETH_HDR_LEN);
    auto etherType = (size_t)_ntohs(ethHdr->etherType);
    auto result = ResSuccess;
    log(LLDebug, "Ethernet Frame: \n");
    log(LLDebug, " SRC MAC: %s\n DST MAC: %s\n Ether Type: %#04x (%hu)\n",
        etherAddrToStr(&ethHdr->srcMacAddr),
        etherAddrToStr(&ethHdr->dstMacAddr),
        etherType,
        etherType);

    if (etherType < NON_ETHER_MAX_LEN) {
        log(LLDebug, "packet is not ethernet II\n");
        printBytes(ethPayload, ethPayloadLen);
        processLLCFrame(pktData, ptr);
    }
    else if (etherType >= ETHER_TYPE_MIN_VAL) {
        log(LLDebug, "packet is ethernet II\n");
        if (etherType == ETypeIP) {
            processIPFrame(pktData, ptr);
        }
        else if (etherType == ETypeARP) {
            processARPFrame(pktData, ptr);
        }
        else if (etherType == ETypeIPV6) {
            log(LLDebug, "next header is IPV6\n");
            // TODO: implement IPV6 parsing
        }
        else if (etherType == ETypeLLDP) {
            log(LLDebug, "next header is LLDP\n");
            // TODO: implement LLDP parsing
        }
        else if (etherType == 0x9104) {
            log(LLWarning, "anomalous ether type 0x9104\n");
            printBytes(ethPayload, ethPayloadLen);
        }
        else {
            log(LLWarning, "unhandled etherType: %hu\n", etherType);
            printBytes(ethPayload, ethPayloadLen);
        }
    }
    else {
        log(LLWarning, "invalid etherType: %hu\n", etherType);
    }

    return result;
}