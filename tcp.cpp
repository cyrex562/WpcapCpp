#include "tcp.h"
#include <cstdint>
#include <vector>
#include "utils.h"



/*
* Process a TCP Frame
*/
void processTCPFrame(std::vector<PacketInfo> packet_table, 
                        size_t index, 
                        uint32_t ipPayloadLen) {
    Log(LLDebug, "TCP Frame:\n");
    auto pkt_info = packet_table[index];
    auto tcpHdr = (struct TCPHeader*)&pkt_info.data[pkt_info.data_ptr];
    auto dstPort = NToHS(tcpHdr->dstPort);
    auto srcPort = NToHS(tcpHdr->srcPort);
    auto dataOffset = tcpHdr->doff * 4;
    auto payloadPtr = pkt_info.data_ptr + dataOffset;
    Log(LLDebug, " SRC Port: %hu\n", srcPort);
    Log(LLDebug, " DST Port: %hu\n", dstPort);
    Log(LLDebug, " Data Offset: %hu\n", tcpHdr->doff);
    Log(LLDebug, " Flags: FIN: %hhu, SYN: %hhu, RST: %hhu, PSH: %hhu, ACK: %hhu, URG: %hhu\n", tcpHdr->fin, tcpHdr->syn, tcpHdr->rst, tcpHdr->psh, tcpHdr->ack, tcpHdr->urg);
    if (dstPort == 5222 || srcPort == 5222) {
        Log(LLDebug, "XMPP frame:\n");
        // TODO: parse XMPP
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 443 || srcPort == 443) {
        Log(LLDebug, "TLS Frame follows:\n");
        // TODO: process TLS frame
    }
    else if (dstPort == 80 || srcPort == 80) {
        Log(LLDebug, "HTTP Frame:\n");
        // TODO: process HTTP frame
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 5671 || srcPort == 5671) {
        Log(LLDebug, "AMQP frame:\n");
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 8009 || srcPort == 8009) {
        Log(LLDebug, "Unknown protocol on port 8009\n");
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 8008 || srcPort == 8008) {
        Log(LLDebug, "Unknown protocol on port 8008\n");
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);

    }
    else if (dstPort == 8060 || srcPort == 8060) {
        Log(LLDebug, "Unknown protocol on port 8060\n");
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 5228 || srcPort == 5228) {
        Log(LLDebug, "Unknown protocol on port 5228\n");
        PrintBytesAndText(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
    else {
        Log(LLWarning, ", unhandled app proto\n");
        PrintBytes(&pkt_info.data[payloadPtr], ipPayloadLen - dataOffset);
    }
}
