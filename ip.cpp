/*
* Convert an IPV4 address to a string.
*/
#include <cstdio>
#include <cstdint>

#include "ip.h"
#include "utils.h"
#include "defines.h"
#include "tcp.h"
#include "igmp.h"
#include "udp.h"

#define _CRT_SECURE_NO_WARNINGS 1

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
    log(LLDebug, "IPv4 Frame:\n");
    auto ipHdr = (struct ipv4Header*)&pktData[ptr];
    size_t ipPayloadLen = _ntohs(ipHdr->totalLength) - (ipHdr->intHdrLen * 4);
    if (ipHdr->intHdrLen > 5) {
        log(LLDebug, " IP header has options\n");
        auto optPtr = ptr + IPV4_HDR_LEN;
        auto optBytes = (ipHdr->intHdrLen * 4) - IPV4_HDR_LEN;
        auto optSpec = (struct IPOptionSpec*)&pktData[optPtr];
        log(LLInfo, "option: %hhu", optSpec->option);
        if (optSpec->option == 4) {
            log(LLDebug, " IP time stamp\n");
        }
        else {
            log(LLWarning, " unk IP Option\n");
        }

    }
    ptr += ipHdr->intHdrLen * 4;
    log(LLDebug, " SRC ADDR: %s\n", ipv4AddrToStr(&ipHdr->srcAddr));
    log(LLDebug, " DST ADDR: %s\n", ipv4AddrToStr(&ipHdr->dstAddr));
    log(LLDebug, " IP Proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
    if (ipHdr->proto == 6) {
        processTCPFrame(pktData, ptr, ipPayloadLen);
    }
    else if (ipHdr->proto == IPPIGMP) {
        processIGMPFrame(pktData, ptr);
    }
    else if (ipHdr->proto == IPPUDP) {
        processUDPFrame(pktData, ptr);
    }
    else if (ipHdr->proto == IPPPIM) {
        // TODO: implement PIM header parsing.
        printBytesAndText(&pktData[ptr], ipPayloadLen);
    }
    else {
        log(LLWarning, "Unhandled IP proto: %02x (%hhu)\n", ipHdr->proto, ipHdr->proto);
    }
}