#pragma once

struct PacketRingBuffer {
    Packet buf[RING_BUF_SZ];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
};

void initRingBuf(struct PacketRingBuffer* packetRingBuffer);
bool ringBufEmpty(struct PacketRingBuffer* packetRingBuffer);
bool ringBufFull(struct PacketRingBuffer* packetRingBuffer);
Packet* ringBufGet(struct PacketRingBuffer* packetRingBuffer);
int ringBufPut(struct PacketRingBuffer* packetRingBuffer,
               struct Packet* packet);
void flushRingBuf(struct PacketRingBuffer* packetRingBuffer);