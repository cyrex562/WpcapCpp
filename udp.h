#pragma once
#include <cstdint>
#include <vector>
#include "defines.h"

struct UDPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t len;
    uint16_t csum;
};

void ProcessUDPFrame(std::vector<PacketInfo> packet_table, size_t index);