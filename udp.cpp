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
    else if (dstPort == 443 || srcPort == 443) {
        printf("TLS UDP frame follows\n");
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
