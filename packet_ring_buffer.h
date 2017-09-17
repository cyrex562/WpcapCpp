#pragma once
#include "ethernet.h"
#include <cstdint>

struct RingBufElement
{
    PacketInfo packet;
    uint8_t completed;
    uint16_t refCount;
};

typedef struct PacketRingBuffer {
    RingBufElement buf[RING_BUF_SZ];
    size_t head;
    size_t tail;
    size_t size;
} PacketRingBuffer;

Result ResetRingBuf(PacketRingBuffer* prb);
bool RingBufEmpty(PacketRingBuffer* packetRingBuffer);
bool RingBufFull(PacketRingBuffer* packetRingBuffer);
Result GetRingBufEle(PacketRingBuffer* packetRingBuffer, 
                     RingBufElement* data);
Result PushRingBufEle(PacketRingBuffer* packetRingBuffer,
                      RingBufElement* packet);