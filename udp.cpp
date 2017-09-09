#include <cstdint>
#include <cstdio>
#include "utils.h"

#include "udp.h"


/*
* Process a UDP Frame
*/
void processUDPFrame(const uint8_t* pktData, uint32_t ptr) {
    auto udpHdr = (struct UDPHeader*)&pktData[ptr];
    uint16_t srcPort = _ntohs(udpHdr->srcPort);
    uint16_t dstPort = _ntohs(udpHdr->dstPort);
    ptr += 8;
    uint8_t* udpPayload = (uint8_t*)(&pktData[ptr]);
    size_t payloadLength = (size_t)(_ntohs(udpHdr->len));
    log(LLDebug, "UDP Frame:\n");
    log(LLDebug, " SRC Port: %hu\n", srcPort);
    log(LLDebug, " DST Port: %hu\n", dstPort);
    log(LLDebug, " Payload Len: %hu\n", payloadLength);
    if (srcPort == 5353 || dstPort == 5353) {
        log(LLDebug, "MDNS Frame:\n");
        // TODO: implement multicast header parsing
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 1900 || dstPort == 1900) {
        log(LLDebug, "SSDP Frame:\n");
        // TODO: implement SSDP frame parsing.
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 137 || dstPort == 137) {
        log(LLDebug, "netbios name service frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 138 || dstPort == 138) {
        log(LLDebug, "netbios data gram service frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort == 49153) {
        log(LLDebug, "temperature sensor frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 5355 || dstPort == 5355) {
        log(LLDebug, "LLMNR frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 53 || dstPort == 53) {
        log(LLDebug, "DNS frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 123 || dstPort == 123) {
        log(LLDebug, "NTP frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 3702 || dstPort == 3702) {
        log(LLDebug, "ws-discovery:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort == 67 || srcPort == 67 || dstPort == 68 || srcPort == 68) {
        log(LLDebug, "DHCP frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort == 443 || srcPort == 443) {
        log(LLDebug, "TLS UDP frame:\n");
        printBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort > 49152) {
        log(LLDebug, "ephemeral or unassigned destination port %hu\n", dstPort);
        printBytesAndText(udpPayload, payloadLength);
    }
    else {
        log(LLWarning, "unhandled port number: src: %hu, dst: %hu\n", srcPort, dstPort);
        printBytesAndText(udpPayload, payloadLength);
    }

}
