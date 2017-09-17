/*
 * @file: utils.cpp
 * @brief: utility functions.
 */
#include "utils.h"
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include "defines.h"

/*
* Logging function
*/
void Log(LogLevel level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    auto output = stdout;
    if (level == LLError || level == LLWarning) {
        output = stderr;
    }

    vfprintf(output, fmt, args);
    va_end(args);
}

void Log(LogLevel level, const char* fmt, va_list args) {
    auto output = stdout;
    if (level == LLError || level == LLWarning) {
        output = stderr;
    }

    vfprintf(output, fmt, args);
}

void LogDebug(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LLDebug, fmt, args);
    va_end(args);
}

void logInfo(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LLInfo, fmt, args);
    va_end(args);
}

void LogWarning(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LLWarning, fmt, args);
    va_end(args);
}

void LogError(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    Log(LLError, fmt, args);
    va_end(args);
}


/*
* Convert a 16-bit value from network to host order.
*/
uint16_t NToHS(uint16_t in16) {
    uint8_t data[2] = {};
    memcpy(&data, &in16, sizeof(data));
    return ((uint16_t)data[1] << 0) | ((uint16_t)data[0] << 8);
}

/*
* Convert a 32-bit value from network to host order.
*/
uint32_t NToHL(uint32_t in32) {
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
void PrintBytes(const uint8_t* bytes, size_t count) {
    Log(LLDebug, "addr: %p, size: %zu, bytes[ ", bytes, count);
    for (size_t i = 0; i < count; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("]\n");
}


void PrintBytesAndText(const uint8_t* bytes, size_t count) {
//OO: BB BB BB BB BB BB BB BB BB BB | T T T T T T T T T T\n
    auto offset = 0;
    auto nonPrintable = '\xfe';
//    auto newLine = true;
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

char *SockAddrFamToStr(int addrFam) {
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

int Endianness(void) {
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

/*
* Convert an Ethernet address to a string.
*/
char* EtherAddrToStr(EthernetAddress* etherAddrBytes) {
    // XX:XX:XX:XX:XX:XX
    static char etherAddrStr[19] = { 0 };
    sprintf(etherAddrStr, "%02X:%02X:%02X:%02X:%02X:%02X",
        etherAddrBytes->addr[0],
        etherAddrBytes->addr[1],
        etherAddrBytes->addr[2],
        etherAddrBytes->addr[3],
        etherAddrBytes->addr[4],
        etherAddrBytes->addr[5]);
    return etherAddrStr;
}

char* IPV4AddrToStr(IPV4Address* in_addr) {
    // XXX.XXX.XXX.XXX
    IPV4Address addr_ho = {};
    static char ipv4_addr_str[16] = { 0 };
    sprintf(ipv4_addr_str, "%hhu.%hhu.%hhu.%hhu",
        in_addr->b[0],
        in_addr->b[1],
        in_addr->b[2],
        in_addr->b[3]);
    return ipv4_addr_str;
}

// END OF FILE