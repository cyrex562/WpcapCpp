#define _WINSOCKAPI_

#include <cstdint>
#include <cstdio>
#include <csignal>
#include <windows.h>

#include "defines.h"
#include "utils.h"
#include "pcap.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "igmp.h"

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

HMODULE hLib;

/*
 * Main entry function.
 */
int main() {
    printf("loading library\n");
    hLib = LoadLibrary("wpcap.dll");
    if (hLib == NULL) {
        printf("failed to load library wpcap.dll\n");
        return -1;
    }

    /*initPcap();*/

    printf("getting proc addrs\n");
    pcapFindAllDevs = (PPCAPFindAllDevs)GetProcAddress(hLib, "pcap_findalldevs");
    if (pcapFindAllDevs == NULL) {
        printf("failed to get proc addr for pcap_findalldevs\n");
        return -1;
    }

    pcapFreeAllDevs = (PFreeAllDevs)GetProcAddress(hLib, "pcap_freealldevs");
    if (pcapFreeAllDevs == NULL) {
        printf("failed to get proc addr for pcap_freealldevs\n");
        return -1;
    }

    pcapOpen = (PPCAPOpen)GetProcAddress(hLib, "pcap_open");
    if (pcapOpen == NULL) {
        printf("failed to get proc addr for pcap_open_live\n");
        return -1;
    }

    pcapNextEx = (PPCAPNextEx)GetProcAddress(hLib, "pcap_next_ex");
    if (pcapNextEx == NULL) {
        printf("failed to get proc addr for pcap_next_ex\n");
        return -1;
    }
     
    char *ifaceName;
    processNetworkInterfaces(&ifaceName);
     
    char errBuf[PCAP_ERR_BUF_SZ] = { 0 };
    auto pcapHandle = pcapOpen(ifaceName,
                               65535,
                               1,
                               1000,
                               NULL,
                               errBuf);
    if (pcapHandle == NULL) {
        printf("pcapOpen failed: %s\n", errBuf);
        return -1;
    }

    struct pcap_pkthdr* pktHdr;
    const unsigned char* pktData;
    while (true) {
        auto result = pcapNextEx(pcapHandle,
                            &pktHdr,
                            &pktData);
        if (result == 0) {
            printf("timeout ocurred\n");
        }
        else if (result == -1) {
            printf("error occurred\n");
            return -1;
        }
        else if (result == -2) {
            printf("EOF occurred\n");
            break;
        }
        else if (result == 1) {
            printf("packet captured\n");
            auto ptr = 0;
            auto ethHdr = (struct EthernetHeader *)(&pktData[ptr]);
            ptr += ETH_HDR_LEN;
            auto ethPayload = (uint8_t*)&pktData[ptr];
            auto ethPayloadLen = (size_t)(pktHdr->caplen - ETH_HDR_LEN);

            printf("src mac addr: %s ", etherAddrToStr(&ethHdr->srcMacAddr));
            printf("dst mac addr: %s ", etherAddrToStr(&ethHdr->dstMacAddr));
            auto etherType = (size_t)_ntohs(ethHdr->etherTypeNO);
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
            return -1;
        }
    }

    return 0;
}
