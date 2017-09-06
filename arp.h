#pragma once

struct ARPHeader {
    uint16_t hType;
    uint16_t pType;
    uint8_t hLen;
    uint8_t pLen;
    uint16_t operation;
    EthernetAddress sndHWAddr;
    IPV4Address sndProtoAddr;
    EthernetAddress tgtHWAddr;
    IPV4Address tgtProtoAddr;
};

void processARPFrame(const uint8_t* pktData, uint32_t ptr);