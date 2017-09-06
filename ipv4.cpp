/*
* Convert an IPV4 address to a string.
*/
#include <cstdio>
#include <cstdint>

#include "ipv4.h"
#include "utils.h"
#include "defines.h"
#include "tcp.h"
#include "igmp.h"
#include "udp.h"

#define _CRT_SECURE_NO_WARNINGS

char* ipv4AddrToStr(IPV4Address* inAddr) {
    // XXX.XXX.XXX.XXX
    IPV4Address addrHO = {};
    static char ipv4AddrStr[16] = { 0 };
    sprintf(ipv4AddrStr, "%hhu.%hhu.%hhu.%hhu",
        inAddr->b[0],
        inAddr->b[1],
        inAddr->b[2],
        inAddr->b[3]);
    return ipv4AddrStr;
}

/*
* Process an IP Frame.
*/
void processIPFrame(const uint8_t* pktData, uint32_t ptr) {
    printf("next header is IPv4\n");
    auto ipHdr = (struct ipv4Header*)&pktData[ptr];
    size_t ipPayloadLen = _ntohs(ipHdr->totalLength) - (ipHdr->intHdrLen * 4);
    if (ipHdr->intHdrLen > 5) {
        printf("IP header has options\n");
        auto optPtr = ptr + IPV4_HDR_LEN;
        auto optBytes = (ipHdr->intHdrLen * 4) - IPV4_HDR_LEN;
        auto optSpec = (struct IPOptionSpec*)&pktData[optPtr];
        printf("option: %hhu ", optSpec->option);
        if (optSpec->option == 4) {
            printf(" IP time stamp\n");
        }
        else {
            printf(" Unhandled IP Option: %hhu\n", optSpec->option);
        }

    }
    ptr += ipHdr->intHdrLen * 4;
    printf("src addr: %s ", ipv4AddrToStr(&ipHdr->srcAddr));
    printf("dst addr: %s ", ipv4AddrToStr(&ipHdr->dstAddr));
    printf("proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
    if (ipHdr->proto == 6) {
        printf("tcp header follows\n");
        processTCPFrame(pktData, ptr, ipPayloadLen);
    }
    else if (ipHdr->proto == IPPIGMP) {
        printf("IGMP header follows\n");
        processIGMPFrame(pktData, ptr);
    }
    else if (ipHdr->proto == IPPUDP) {
        printf("UDP header follows\n");
        processUDPFrame(pktData, ptr);
    }
    else if (ipHdr->proto == IPPPIM) {
        printf("PIM header follows\n");
        // TODO: implement PIM header parsing.
    }
    else {
        printf("unhandled IP proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
    }
}