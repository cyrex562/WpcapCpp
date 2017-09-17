/**
 * @file packetringbuffer.cpp
 */
#include "packet_ring_buffer.h"
#include <cstring>

#include "defines.h"
#include "utils.h"


/*
 * FUNCTIONS
 */

/*
 * Initalize a ring buffer data struct.
 */
Result ResetRingBuf(PacketRingBuffer* prb) {
    LogDebug("initializing ring buffer\n");

    if (!prb) {
        LogWarning("%s: prb cannot be null\n", __func__);
        return ResError;
    }
        

    memset(prb, 0, sizeof(prb));
    prb->head = 0;
    prb->tail = 0;

    return ResSuccess;
}

/*
 * Check if the ring buffer is empty. The ring buffer should be empty when its size element is 0.
 */
bool RingBufEmpty(PacketRingBuffer* prb) {
    auto empty = (prb->head == prb->tail);
    if (empty == false) {
        Log(LLDebug, "ring buffer is not empty\n");
    } else {
        Log(LLDebug, "ring buffer is empty\n");
    }

    return empty;
}

/**
 * Check if the ring buffer is full.The ring buffer should be full when its size equals its size.
 */
bool RingBufFull(struct PacketRingBuffer* prb) {
    auto full = ((prb->head + 1) % (prb->size == prb->tail));
    if (full == 0) {
        Log(LLDebug, "ring buffer is not full\n");
        return false;
    }
    Log(LLDebug, "ring buffer is full\n");
    return true;
}

/*
 * Retrieve an element from the ring buffer.
 */
Result GetRingBufEle(PacketRingBuffer* prb,
                     RingBufElement* data) {

    if (!prb) {
        LogWarning("%s: prb cannot be null\n", __func__);
        return ResError;

    }

    if (!data) {
        LogWarning("%s: data cannot be null\n", __func__);
        return ResError;
    }

    if (RingBufEmpty(prb)) {
        LogWarning("%s: empty ring buf\n", __func__);
        return ResError;
    }

    memcpy(data, &prb->buf[prb->tail], sizeof(RingBufElement));
    prb->tail = (prb->tail + 1) % prb->size;
    LogDebug("%s: prb: %p, tail: %u\n", prb, prb->tail);
    return ResSuccess;
}

/*
 * push an element into the ring buffer
 */
Result PushRingBufEle(struct PacketRingBuffer* prb,
                   struct PacketInfo* packet) {
    if (!prb) {
        Log(LLWarning, "%s: prb cannot be null\n", __func__);
        return ResError;
    }

    memcpy(&prb->buf[prb->head], packet, sizeof(PacketInfo));
    prb->head = (prb->head + 1) % prb->size;

    if (prb->head == prb->tail) {
        prb->tail = (prb->tail + 1) % prb->size;
        LogDebug("%s: wrapping tail to head\n", __func__);
    }

    Log(LLDebug, "prb: %p, head: %u, tail: %u\n", prb, prb->head, prb->tail);
    return ResSuccess;
}

