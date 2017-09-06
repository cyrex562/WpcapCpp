#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>

#include "defines.h"
#include "utils.h"



/*
* Logging function
*/
void log(LogLevel level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    auto output = stdout;
    if (level == LLError || level == LLWarning) {
        output = stderr;
    }

    vfprintf(output, fmt, args);
    va_end(args);
}


/*
* Convert a 16-bit value from network to host order.
*/
uint16_t _ntohs(uint16_t in16) {
    uint8_t data[2] = {};
    memcpy(&data, &in16, sizeof(data));
    return ((uint16_t)data[1] << 0) | ((uint16_t)data[0] << 8);
}

/*
* Convert a 32-bit value from network to host order.
*/
uint32_t _ntohl(uint32_t in32) {
    uint8_t data[4] = {};
    memcpy(&data, &in32, sizeof(data));
    return ((uint32_t)data[3] << 0)
        | ((uint32_t)data[2] << 8)
        | ((uint32_t)data[1] << 16)
        | ((uint32_t)data[0] << 24);
}

/*
* Print a byte sequence.
*/
void printBytes(const uint8_t* bytes, size_t count) {
    printf("addr: %p, count: %zu, bytes[ ", bytes, count);
    for (size_t i = 0; i < count; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("]\n");
}