#include <cstring>
#include <cstdint>


#include "defines.h"
#include "utils.h"

#include "PacketRingBuffer.h"


/*
 * Initalize a ring buffer data struct.
 */
void initRingBuf(struct PacketRingBuffer* packetRingBuffer) {
    /*
     * Clear buf, head, tail, and count; 
     * Set head = tail
     */
	log(LLDebug, "initializing ring buffer\n");
    memset(packetRingBuffer, 0, sizeof(packetRingBuffer));
}

/*
 * Check if the ring buffer is empty. The ring buffer should be empty when its count element is 0.
 */
bool ringBufEmpty(struct PacketRingBuffer* packetRingBuffer) {
	auto empty = packetRingBuffer->count == 0;
	if (empty == false)
	{
		log(LLDebug, "ring buffer is not empty\n");
	} else
	{
		log(LLDebug, "ring buffer is empty\n");
	}

	return empty;
}

/**
 * Check if the ring buffer is full.The ring buffer should be full when its count equals its size.
 */
bool ringBufFull(struct PacketRingBuffer* packetRingBuffer) {
    return (packetRingBuffer->count >= RING_BUF_SZ);
}

/*
 * Retrieve an element from the ring buffer.
 */
RingBufElement* getRingBufEle(struct PacketRingBuffer* packetRingBuffer) {
    static RingBufElement packet = { 0 };z

    if (packetRingBuffer->count > 0) {
        memcpy(&packet, &packetRingBuffer->buf[packetRingBuffer->tail], sizeof(RingBufElement));

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

int pushRingBufEle(struct PacketRingBuffer* packetRingBuffer,
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

