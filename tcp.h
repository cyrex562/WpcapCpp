#pragma once

struct TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    // syn = 1: initial seq num; else, sequence number plus 1
    uint32_t seqNum;
    // next sequence number sender is expecting
    uint32_t ackNum;
    uint16_t res1 : 4;
    // the size of the tcp header in dwords
    uint16_t doff : 4;
    uint16_t fin : 1;
    uint16_t syn : 1;
    uint16_t rst : 1;
    uint16_t psh : 1;
    uint16_t ack : 1;
    uint16_t urg : 1;
    uint16_t res2 : 2;
    // the size of the receive window, in bytes
    uint16_t winSz;
    uint16_t csum;
    uint16_t urgPtr;
};

void processTCPFrame(const uint8_t* pktData, uint32_t ptr, uint32_t ipPayloadLen);