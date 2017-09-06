#pragma once

struct UDPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t len;
    uint16_t csum;
};

void processUDPFrame(const uint8_t* pktData, uint32_t ptr);