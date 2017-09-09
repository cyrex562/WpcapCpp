#include <cstdint>
#include <cstdio>
#include "utils.h"

#include "tcp.h"

/*
* Process a TCP Frame
*/
void processTCPFrame(const uint8_t* pktData, uint32_t ptr, uint32_t ipPayloadLen) {
    log(LLDebug, "TCP Frame:\n");
    auto tcpHdr = (struct TCPHeader*)&pktData[ptr];
    auto dstPort = _ntohs(tcpHdr->dstPort);
    auto srcPort = _ntohs(tcpHdr->srcPort);
    auto dataOffset = tcpHdr->doff * 4;
    auto payloadPtr = ptr + dataOffset;
    log(LLDebug, " SRC Port: %hu\n", srcPort);
    log(LLDebug, " DST Port: %hu\n", dstPort);
    log(LLDebug, " Data Offset: %hu\n", tcpHdr->doff);
    log(LLDebug, " Flags: FIN: %hhu, SYN: %hhu, RST: %hhu, PSH: %hhu, ACK: %hhu, URG: %hhu\n", tcpHdr->fin, tcpHdr->syn, tcpHdr->rst, tcpHdr->psh, tcpHdr->ack, tcpHdr->urg);
    if (dstPort == 5222 || srcPort == 5222) {
        log(LLDebug, "XMPP frame:\n");
        // TODO: parse XMPP
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 443 || srcPort == 443) {
        log(LLDebug, "TLS Frame follows:\n");
        // TODO: process TLS frame
    }
    else if (dstPort == 80 || srcPort == 80) {
        log(LLDebug, "HTTP Frame:\n");
        // TODO: process HTTP frame
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 5671 || srcPort == 5671) {
        log(LLDebug, "AMQP frame:\n");
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 8009 || srcPort == 8009) {
        log(LLDebug, "Unknown protocol on port 8009\n");
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 8008 || srcPort == 8008) {
        log(LLDebug, "Unknown protocol on port 8008\n");
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);

    }
    else if (dstPort == 8060 || srcPort == 8060) {
        log(LLDebug, "Unknown protocol on port 8060\n");
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
    else if (dstPort == 5228 || srcPort == 5228) {
        log(LLDebug, "Unknown protocol on port 5228\n");
        printBytesAndText(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
    else {
        log(LLWarning, ", unhandled app proto\n");
        printBytes(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
}
