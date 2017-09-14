#include <cstring>
#include <cstdint>

#include "defines.h"

#include "PacketRingBuffer.h"


void initRingBuf(struct PacketRingBuffer* packetRingBuffer) {
    /*
     * Clear buf, head, tail, and count; 
     * Set head = tail
     */
    memset(packetRingBuffer, 0, sizeof(packetRingBuffer));
}

bool ringBufEmpty(struct PacketRingBuffer* packetRingBuffer) {
    return (packetRingBuffer->count == 0);
}

bool ringBufFull(struct PacketRingBuffer* packetRingBuffer) {
    return (packetRingBuffer->count >= RING_BUF_SZ);
}

Packet* ringBufGet(struct PacketRingBuffer* packetRingBuffer) {
    static Packet packet = { 0 };

    if (packetRingBuffer->count > 0) {
        memcpy(&packet, &packetRingBuffer->buf[packetRingBuffer->tail], sizeof(Packet));

        if (packetRingBuffer->count + 1 < RING_BUF_SZ) {
            packetRingBuffer->tail++;
        } else {
            packetRingBuffer->tail = RING_BUF_SZ;
        }
        return &packet;
    } else {
        return NULL;
    }
}

int ringBufPut(struct PacketRingBuffer* packetRingBuffer,
                struct Packet* packet) {
    int result = 0;
    if (packetRingBuffer->count < RING_BUF_SZ) {
        memcpy(&packetRingBuffer->buf[packetRingBuffer->head], packet, sizeof(Packet));
    } else {
        result = -1;
    }
    return result;
}

void flushRingBuf(struct PacketRingBuffer* packetRingBuffer) {
    packetRingBuffer->count = 0;
    packetRingBuffer->head = 0;
    packetRingBuffer->tail = 0;
    memset(packetRingBuffer->buf, 0, sizeof(packetRingBuffer->buf));
}

