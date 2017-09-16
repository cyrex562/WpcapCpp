#pragma once

struct RingBufElement
{
	Packet packet;
	uint8_t completed;
	uint16_t refCount;
};

struct PacketRingBuffer {
    RingBufElement buf[RING_BUF_SZ];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
};

void initRingBuf(struct PacketRingBuffer* packetRingBuffer);
bool ringBufEmpty(struct PacketRingBuffer* packetRingBuffer);
bool ringBufFull(struct PacketRingBuffer* packetRingBuffer);
RingBufElement* getRingBufEle(struct PacketRingBuffer* packetRingBuffer);
int pushRingBufEle(struct PacketRingBuffer* packetRingBuffer,
                  struct RingBufElement* packet);
void flushRingBuf(struct PacketRingBuffer* packetRingBuffer);