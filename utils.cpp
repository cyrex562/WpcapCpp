/*
 * @file: utils.cpp
 * @brief: utility functions.
 */
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
    log(LLDebug, "addr: %p, count: %zu, bytes[ ", bytes, count);
    for (size_t i = 0; i < count; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("]\n");
}


void printBytesAndText(const uint8_t* bytes, size_t count) {
//OO: BB BB BB BB BB BB BB BB BB BB | T T T T T T T T T T\n
    auto offset = 0;
    auto nonPrintable = '\xfe';
    auto newLine = true;
    size_t j = 0;
    for (size_t i = 0; i<  count; i++) {
        printf("%04x: ", offset);

        for (j = 0; j < 10; j++) {
            if (i + j >= count) {
                printf("XX ");
            } else {
                printf("%02x ", bytes[i + j]);
            }
        } 

        printf("| ");

        for (j = 0; j < 10; j++) {
            if (i + j >= count) {
                printf("%c ", 178);
            } else {
                auto ch = bytes[i + j];
                if (ch < 20 || ch > 127) {
                    ch = nonPrintable;
                }

                printf("%c ", ch);
            }
        }

        printf("\n");
        i += j - 1;
        offset += 10;
    }
}

char *addrFamToStr(int addrFam) {
    static char addrFamStr[64] = { 0 };
    if (addrFam == AF_UNSPEC) {
        sprintf(addrFamStr, "%s", "AF_UNSPEC");
    } else if (addrFam == AF_UNIX) {
        sprintf(addrFamStr, "%s", "AF_UNIX");
    } else if (addrFam == AF_INET) {
        sprintf(addrFamStr, "%s", "AF_INET");
    } else if (addrFam == AF_INET6) {
        sprintf(addrFamStr, "%s", "AF_INET6");
    } else if (addrFam == AF_NETLINK) {
        sprintf(addrFamStr, "%s", "AF_NETLINK/AF_ROUTE");
    } else if (addrFam == AF_PACKET) {
        sprintf(addrFamStr, "%s", "AF_PACKET");
    } else if (addrFam == AF_LLC) {
        sprintf(addrFamStr, "%s", "AF_LLC");
    } else if (addrFam == AF_BLUETOOTH) {
        sprintf(addrFamStr, "%s", "AF_BLUETOOTH");
    } else if (addrFam == AF_BRIDGE) {
        sprintf(addrFamStr, "%s", "AF_BRIDGE");
    } else {
        sprintf(addrFamStr, "%i", addrFam);
    }
    return addrFamStr;
}

int endianness(void) {
    union {
        uint32_t value;
        uint8_t data[sizeof(uint32_t)];
    } number;

    number.data[0] = 0x00;
    number.data[1] = 0x01;
    number.data[2] = 0x02;
    number.data[3] = 0x03;

    switch (number.value) {
    case UINT32_C(0x00010203): return EndianBig;
    case UINT32_C(0x03020100): return EndianLittle;
    default: return EndianUnkown;
    }

}

// END OF FILE