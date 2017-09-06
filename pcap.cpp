#include <cstdio>
#include <cstdint>

#include "pcap.h"
#include "defines.h"
#include <cstring>

#define _CRT_SECURE_NO_WARNINGS

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
int processNetworkInterfaces(char **ifaceName) {
    auto i = 0;
    auto iface_cnt = 0;
    pcap_if_t* interfaces[64] = { 0 };
    pcap_if_t* allDevs;
    uint16_t choice = 0;

    char errBuf[PCAP_ERR_BUF_SZ] = { 0 };
    printf("getting list of devices\n");
    auto result = pcapFindAllDevs(&allDevs, errBuf);
    if (result == -1) {
        printf("error calling pcap_findalldevs: %s\n", errBuf);
        return -1;
    }

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

    printf("select an interface to capture traffic from: ");
    scanf("%hu", &choice);

    static char _ifaceName[0xffff] = { 0 };
    strcat(_ifaceName, "rpcap://");
    strcat(_ifaceName, interfaces[choice]->name);
    *ifaceName = _ifaceName;

    pcapFreeAllDevs(allDevs);

    return 0;
}
