#include "udp.h"
#include <cstdint>
#include "utils.h"
#include <vector>


/*
* Process a UDP Frame
*/
void ProcessUDPFrame(std::vector<PacketInfo> packet_table, size_t index) {
    auto pkt_info = packet_table[index];
    auto udpHdr = (struct UDPHeader*)&pkt_info.data[pkt_info.data_ptr];
    uint16_t srcPort = NToHS(udpHdr->srcPort);
    uint16_t dstPort = NToHS(udpHdr->dstPort);
    pkt_info.data_ptr += 8;
    uint8_t* udpPayload = (uint8_t*)(&pkt_info.data[pkt_info.data_ptr]);
    size_t payloadLength = (size_t)(NToHS(udpHdr->len));
    Log(LLDebug, "UDP Frame:\n");
    Log(LLDebug, " SRC Port: %hu\n", srcPort);
    Log(LLDebug, " DST Port: %hu\n", dstPort);
    Log(LLDebug, " Payload Len: %hu\n", payloadLength);
    if (srcPort == 5353 || dstPort == 5353) {
        Log(LLDebug, "MDNS Frame:\n");
        // TODO: implement multicast header parsing
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 1900 || dstPort == 1900) {
        Log(LLDebug, "SSDP Frame:\n");
        // TODO: implement SSDP frame parsing.
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 137 || dstPort == 137) {
        Log(LLDebug, "netbios name service frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 138 || dstPort == 138) {
        Log(LLDebug, "netbios data gram service frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort == 49153) {
        Log(LLDebug, "temperature sensor frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 5355 || dstPort == 5355) {
        Log(LLDebug, "LLMNR frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 53 || dstPort == 53) {
        Log(LLDebug, "DNS frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 123 || dstPort == 123) {
        Log(LLDebug, "NTP frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (srcPort == 3702 || dstPort == 3702) {
        Log(LLDebug, "ws-discovery:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort == 67 || srcPort == 67 || dstPort == 68 || srcPort == 68) {
        Log(LLDebug, "DHCP frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort == 443 || srcPort == 443) {
        Log(LLDebug, "TLS UDP frame:\n");
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else if (dstPort > 49152) {
        Log(LLDebug, "ephemeral or unassigned destination port %hu\n", dstPort);
        PrintBytesAndText(udpPayload, payloadLength);
    }
    else {
        Log(LLWarning, "unhandled port number: src: %hu, dst: %hu\n", srcPort, dstPort);
        PrintBytesAndText(udpPayload, payloadLength);
    }
}
