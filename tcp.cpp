#include <cstdint>
#include <cstdio>
#include "utils.h"

#include "tcp.h"

/*
* Process a TCP Frame
*/
void processTCPFrame(const uint8_t* pktData, uint32_t ptr, uint32_t ipPayloadLen) {
    auto tcpHdr = (struct TCPHeader*)&pktData[ptr];
    auto dstPort = _ntohs(tcpHdr->dstPort);
    auto srcPort = _ntohs(tcpHdr->srcPort);
    auto dataOffset = tcpHdr->doff * 4;
    auto payloadPtr = ptr + dataOffset;
    printf("src port: %hu", srcPort);
    printf(", dst port: %hu", dstPort);
    printf(", data offset: %hu", tcpHdr->doff);
    printf(", flags: FIN: %hhu, SYN: %hhu, RST: %hhu, PSH: %hhu, ACK: %hhu, URG: %hhu\n", tcpHdr->fin, tcpHdr->syn, tcpHdr->rst, tcpHdr->psh, tcpHdr->ack, tcpHdr->urg);
    if (dstPort == 5222 || srcPort == 5222) {
        printf("XMPP frame follows\n");
        // TODO: parse XMPP
    }
    else if (dstPort == 443 || srcPort == 443) {
        printf("TLS Frame follows\n");
        // TODO: process TLS frame
    }
    else if (dstPort == 5671 || srcPort == 5671) {
        printf("AMQP frame follows\n");
    }
    else {
        printf(", unhandled app proto\n");
        printBytes(&pktData[payloadPtr], ipPayloadLen - dataOffset);
    }
}
